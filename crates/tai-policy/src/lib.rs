//! Policy engine: решает, можно ли агенту выполнить действие над ресурсом.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub effect: Effect,
    pub agent: String,
    pub action: String,
    pub resource: String,
}

impl Rule {
    fn matches(&self, agent: &str, action: &str, resource: &str) -> bool {
        glob(&self.agent, agent) && glob(&self.action, action) && glob(&self.resource, resource)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// Deny важнее allow; всё, что не разрешено явно, запрещено.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    rules: Vec<Rule>,
}

impl Policy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow(mut self, agent: &str, action: &str, resource: &str) -> Self {
        self.rules.push(Rule {
            effect: Effect::Allow,
            agent: agent.into(),
            action: action.into(),
            resource: resource.into(),
        });
        self
    }

    pub fn deny(mut self, agent: &str, action: &str, resource: &str) -> Self {
        self.rules.push(Rule {
            effect: Effect::Deny,
            agent: agent.into(),
            action: action.into(),
            resource: resource.into(),
        });
        self
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn check(&self, agent: &str, action: &str, resource: &str) -> Decision {
        // первый подошедший deny выигрывает, allow просто запоминается
        let mut allowed = false;
        for rule in &self.rules {
            if !rule.matches(agent, action, resource) {
                continue;
            }
            match rule.effect {
                Effect::Deny => {
                    return Decision::Deny {
                        reason: "explicit deny rule".into(),
                    }
                }
                Effect::Allow => allowed = true,
            }
        }
        if allowed {
            Decision::Allow
        } else {
            Decision::Deny {
                reason: "default deny".into(),
            }
        }
    }

    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn to_json(&self) -> Result<String, PolicyError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Глоб: `*` — любая последовательность символов, остальное — литералы.
fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;

    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            // откат к последней звёздочке и попытка захватить ещё символ
            ti = st + 1;
            pi = sp + 1;
            star = Some((sp, ti));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::new()
            .allow("agent-1", "tool.call", "web.get:*")
            .allow("agent-*", "model.invoke", "model:*")
            .deny("*", "tool.call", "fs.write:/etc/*")
    }

    #[test]
    fn default_deny() {
        assert!(!policy()
            .check("agent-9", "tool.call", "web.get:x")
            .is_allowed());
        assert!(!policy()
            .check("agent-1", "tool.exec", "shell:*")
            .is_allowed());
    }

    #[test]
    fn allow_with_wildcards() {
        let p = policy();
        assert!(p
            .check("agent-1", "tool.call", "web.get:example.com")
            .is_allowed());
        assert!(p
            .check("agent-77", "model.invoke", "model:qwen")
            .is_allowed());
    }

    #[test]
    fn deny_overrides_allow() {
        let p = Policy::new()
            .allow("a", "tool.call", "*")
            .deny("a", "tool.call", "fs.write:*");
        assert!(!p.check("a", "tool.call", "fs.write:/etc").is_allowed());
        assert!(p.check("a", "tool.call", "web.get:ok").is_allowed());
    }

    #[test]
    fn wildcard_in_action() {
        let p = Policy::new().allow("a", "*", "x");
        assert!(p.check("a", "anything", "x").is_allowed());
        assert!(!p.check("a", "anything", "y").is_allowed());
    }

    #[test]
    fn json_roundtrip() {
        let p = policy();
        let restored = Policy::from_json(&p.to_json().unwrap()).unwrap();
        assert_eq!(
            restored.check("agent-1", "tool.call", "web.get:x"),
            Decision::Allow
        );
        assert_eq!(
            restored.check("agent-1", "tool.call", "fs.write:/etc/passwd"),
            Decision::Deny {
                reason: "explicit deny rule".into()
            }
        );
    }
}
