//! Агент: действия проходят через policy и пишутся в аудит.

use std::sync::Arc;

use tai_audit::AuditLog;
use tai_core::Event;
use tai_models::{CompletionRequest, ModelError, Router};
use tai_policy::Decision;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("denied: {0}")]
    Denied(String),
    #[error("model: {0}")]
    Model(#[from] ModelError),
}

pub struct Agent {
    pub id: String,
    router: Arc<Router>,
    policy: Arc<tai_policy::Policy>,
    audit: Arc<AuditLog>,
}

impl Agent {
    pub fn new(
        id: impl Into<String>,
        router: Arc<Router>,
        policy: Arc<tai_policy::Policy>,
        audit: Arc<AuditLog>,
    ) -> Self {
        Self {
            id: id.into(),
            router,
            policy,
            audit,
        }
    }

    /// Запрос к модели через policy-гейт (action = model.invoke).
    pub fn ask(&self, prompt: &str) -> Result<String, AgentError> {
        self.ensure_allowed("model.invoke", "model:*")?;
        let resp = self.router.complete(&CompletionRequest::new(prompt))?;
        self.audit.log(&Event::now(
            "model.invoke",
            &self.id,
            format!("model={} len={}", resp.model, resp.text.len()),
        ));
        Ok(resp.text)
    }

    /// Гейт любого действия: проверка policy + событие в аудит.
    pub fn ensure_allowed(&self, action: &str, resource: &str) -> Result<(), AgentError> {
        match self.policy.check(&self.id, action, resource) {
            Decision::Allow => {
                self.audit.log(&Event::now(
                    "policy.allow",
                    &self.id,
                    format!("{action} {resource}"),
                ));
                Ok(())
            }
            Decision::Deny { reason } => {
                self.audit.log(&Event::now(
                    "policy.deny",
                    &self.id,
                    format!("{action} {resource} {reason}"),
                ));
                Err(AgentError::Denied(reason))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tai_models::Echo;
    use tai_policy::Policy;

    fn agent(id: &str, policy: Policy) -> Agent {
        Agent::new(
            id,
            Arc::new(Router::new().register(Arc::new(Echo::new("echo")))),
            Arc::new(policy),
            Arc::new(AuditLog::stderr()),
        )
    }

    #[test]
    fn ask_passes_gate_and_routes() {
        let a = agent("a1", Policy::new().allow("a1", "model.invoke", "model:*"));
        assert_eq!(a.ask("hello").unwrap(), "hello");
    }

    #[test]
    fn ask_denied_without_rule() {
        let a = agent("a2", Policy::new());
        assert!(matches!(a.ask("hello"), Err(AgentError::Denied(_))));
    }

    #[test]
    fn ensure_allowed_respects_deny() {
        let a = agent(
            "a3",
            Policy::new()
                .allow("a3", "tool.call", "*")
                .deny("a3", "tool.call", "fs.write:*"),
        );
        assert!(a.ensure_allowed("tool.call", "web.get:x").is_ok());
        assert!(matches!(
            a.ensure_allowed("tool.call", "fs.write:/etc"),
            Err(AgentError::Denied(_))
        ));
    }
}
