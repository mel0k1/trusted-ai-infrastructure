//! Агент: действия проходят через policy и пишутся в аудит; sync и async.

use std::sync::Arc;

use tai_audit::AuditLog;
use tai_core::Event;
use tai_models::{AsyncRouter, CompletionRequest, DeltaSink, ModelError, Router};
use tai_policy::{Decision, Policy};
use tai_sandbox::{Sandbox, ToolError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("denied: {0}")]
    Denied(String),
    #[error("model: {0}")]
    Model(#[from] ModelError),
    #[error("tool: {0}")]
    Tool(#[from] ToolError),
}

/// Общий гейт для sync и async агентов: проверка policy + событие в аудит.
fn gate(
    policy: &Policy,
    actor: &str,
    action: &str,
    resource: &str,
    audit: &AuditLog,
) -> Result<(), AgentError> {
    match policy.check(actor, action, resource) {
        Decision::Allow => {
            audit.log(&Event::now(
                "policy.allow",
                actor,
                format!("{action} {resource}"),
            ));
            Ok(())
        }
        Decision::Deny { reason } => {
            audit.log(&Event::now(
                "policy.deny",
                actor,
                format!("{action} {resource} {reason}"),
            ));
            Err(AgentError::Denied(reason))
        }
    }
}

pub struct Agent {
    pub id: String,
    router: Arc<Router>,
    policy: Arc<Policy>,
    audit: Arc<AuditLog>,
}

impl Agent {
    pub fn new(
        id: impl Into<String>,
        router: Arc<Router>,
        policy: Arc<Policy>,
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
        gate(
            &self.policy,
            &self.id,
            "model.invoke",
            "model:*",
            &self.audit,
        )?;
        let resp = self.router.complete(&CompletionRequest::new(prompt))?;
        self.audit.log(&Event::now(
            "model.invoke",
            &self.id,
            format!("model={} len={}", resp.model, resp.text.len()),
        ));
        Ok(resp.text)
    }

    pub fn ensure_allowed(&self, action: &str, resource: &str) -> Result<(), AgentError> {
        gate(&self.policy, &self.id, action, resource, &self.audit)
    }
}

/// Async-версия: роутер и sandbox на tokio.
pub struct AsyncAgent {
    pub id: String,
    router: Arc<AsyncRouter>,
    policy: Arc<Policy>,
    audit: Arc<AuditLog>,
    sandbox: Arc<Sandbox>,
}

impl AsyncAgent {
    pub fn new(
        id: impl Into<String>,
        router: Arc<AsyncRouter>,
        policy: Arc<Policy>,
        audit: Arc<AuditLog>,
        sandbox: Arc<Sandbox>,
    ) -> Self {
        Self {
            id: id.into(),
            router,
            policy,
            audit,
            sandbox,
        }
    }

    pub async fn ask(&self, prompt: &str) -> Result<String, AgentError> {
        gate(
            &self.policy,
            &self.id,
            "model.invoke",
            "model:*",
            &self.audit,
        )?;
        let resp = self
            .router
            .complete(&CompletionRequest::new(prompt))
            .await?;
        self.audit.log(&Event::now(
            "model.invoke",
            &self.id,
            format!("model={} len={}", resp.model, resp.text.len()),
        ));
        Ok(resp.text)
    }

    /// Стриминг ответа модели через гейт; дельты в sink.
    pub async fn ask_stream(
        &self,
        prompt: &str,
        on_delta: &mut dyn DeltaSink,
    ) -> Result<String, AgentError> {
        gate(
            &self.policy,
            &self.id,
            "model.invoke",
            "model:*",
            &self.audit,
        )?;
        let resp = self
            .router
            .stream(&CompletionRequest::new(prompt), on_delta)
            .await?;
        self.audit.log(&Event::now(
            "model.invoke",
            &self.id,
            format!("model={} len={} stream=true", resp.model, resp.text.len()),
        ));
        Ok(resp.text)
    }

    /// Инструмент: policy на {tool}:{input}, затем sandbox.
    pub async fn call_tool(&self, name: &str, input: &str) -> Result<String, AgentError> {
        gate(
            &self.policy,
            &self.id,
            "tool.call",
            &format!("{name}:{input}"),
            &self.audit,
        )?;
        let out = self.sandbox.execute(name, input).await?;
        self.audit.log(&Event::now(
            "tool.call",
            &self.id,
            format!("{name} len={}", out.len()),
        ));
        Ok(out)
    }

    pub fn ensure_allowed(&self, action: &str, resource: &str) -> Result<(), AgentError> {
        gate(&self.policy, &self.id, action, resource, &self.audit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tai_models::Echo;
    use tai_sandbox::{EchoTool, Limits};

    fn agent(id: &str, policy: Policy) -> Agent {
        Agent::new(
            id,
            Arc::new(Router::new().register(Arc::new(Echo::new("echo")))),
            Arc::new(policy),
            Arc::new(AuditLog::stderr()),
        )
    }

    fn async_agent(policy: Policy) -> AsyncAgent {
        AsyncAgent::new(
            "a",
            Arc::new(AsyncRouter::new().register_sync(Arc::new(Echo::new("echo")))),
            Arc::new(policy),
            Arc::new(AuditLog::stderr()),
            Arc::new(Sandbox::new(Limits::default()).register(Arc::new(EchoTool))),
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

    #[tokio::test]
    async fn async_agent_ask_and_tool_flow() {
        let a = async_agent(Policy::new().allow("a", "model.invoke", "model:*").allow(
            "a",
            "tool.call",
            "echo:*",
        ));
        assert_eq!(a.ask("hi").await.unwrap(), "hi");
        assert_eq!(a.call_tool("echo", "ping").await.unwrap(), "ping");
    }

    #[tokio::test]
    async fn async_agent_denies_tool_by_default() {
        let a = async_agent(Policy::new().allow("a", "model.invoke", "model:*"));
        assert!(matches!(
            a.call_tool("echo", "x").await,
            Err(AgentError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn async_agent_unknown_tool_not_found() {
        let a = async_agent(Policy::new().allow("a", "tool.call", "*"));
        assert!(matches!(
            a.call_tool("nope", "x").await,
            Err(AgentError::Tool(ToolError::NotFound(_)))
        ));
    }

    #[tokio::test]
    async fn async_agent_streams_through_gate() {
        let a = async_agent(Policy::new().allow("a", "model.invoke", "model:*"));
        let mut seen = String::new();
        let text = a
            .ask_stream("hi", &mut |d: &str| seen.push_str(d))
            .await
            .unwrap();
        assert_eq!(text, "hi");
        // echo без стриминга — дельт нет
        assert!(seen.is_empty());

        let b = async_agent(Policy::new());
        assert!(matches!(
            b.ask_stream("hi", &mut |d: &str| seen.push_str(d)).await,
            Err(AgentError::Denied(_))
        ));
    }
}
