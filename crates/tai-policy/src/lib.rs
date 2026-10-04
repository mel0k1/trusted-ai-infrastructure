//! Policy engine: решает, можно ли агенту выполнить действие над ресурсом.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
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

/// Политика с горячей перезагрузкой из JSON-файла.
pub struct HotPolicy {
    path: PathBuf,
    inner: RwLock<Arc<Policy>>,
    content: Mutex<String>,
    stop: AtomicBool,
}

impl HotPolicy {
    /// Загружает файл; невалидный JSON — ошибка на старте.
    pub fn new(path: impl AsRef<Path>) -> Result<Arc<Self>, PolicyError> {
        let path = path.as_ref().to_path_buf();
        let content = fs::read_to_string(&path)?;
        let policy: Policy = serde_json::from_str(&content)?;
        Ok(Arc::new(Self {
            path,
            inner: RwLock::new(Arc::new(policy)),
            content: Mutex::new(content),
            stop: AtomicBool::new(false),
        }))
    }

    /// Свежий снапшот политики.
    pub fn get(&self) -> Arc<Policy> {
        self.inner.read().expect("policy lock").clone()
    }

    pub fn check(&self, agent: &str, action: &str, resource: &str) -> Decision {
        self.get().check(agent, action, resource)
    }

    /// Перечитывает файл; true — политика заменена.
    /// Ошибка чтения/парсинга не трогает работающую политику.
    pub fn reload(&self) -> Result<bool, PolicyError> {
        let content = fs::read_to_string(&self.path)?;
        if content == *self.content.lock().expect("policy lock") {
            return Ok(false);
        }
        let fresh: Policy = serde_json::from_str(&content)?;
        *self.inner.write().expect("policy lock") = Arc::new(fresh);
        *self.content.lock().expect("policy lock") = content;
        Ok(true)
    }

    /// Фоновый опрос файла; остановка через stop().
    pub fn spawn_watcher(self: &Arc<Self>, interval: Duration) -> std::thread::JoinHandle<()> {
        let this = Arc::clone(self);
        std::thread::spawn(move || {
            while !this.stop.load(Ordering::Relaxed) {
                std::thread::sleep(interval);
                let _ = this.reload();
            }
        })
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
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

    fn temp_policy_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tai-policy-{}-{tag}.json", std::process::id()))
    }

    const V1: &str = r#"{"rules":[{"effect":"allow","agent":"a","action":"act","resource":"x"}]}"#;
    const V2: &str = r#"{"rules":[]}"#;

    #[test]
    fn hot_policy_reloads_changed_file() {
        let path = temp_policy_path("reload");
        std::fs::write(&path, V1).unwrap();
        let hp = HotPolicy::new(&path).unwrap();
        assert!(hp.check("a", "act", "x").is_allowed());

        std::fs::write(&path, V2).unwrap();
        assert!(hp.reload().unwrap());
        assert!(!hp.check("a", "act", "x").is_allowed());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn invalid_file_keeps_old_policy() {
        let path = temp_policy_path("invalid");
        std::fs::write(&path, V1).unwrap();
        let hp = HotPolicy::new(&path).unwrap();

        std::fs::write(&path, "not json").unwrap();
        assert!(hp.reload().is_err());
        assert!(hp.check("a", "act", "x").is_allowed());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn watcher_picks_up_changes() {
        let path = temp_policy_path("watcher");
        std::fs::write(&path, V1).unwrap();
        let hp = HotPolicy::new(&path).unwrap();
        let watcher = hp.spawn_watcher(Duration::from_millis(20));

        std::fs::write(&path, V2).unwrap();
        // ждём, пока фоновый поток заметит изменение
        for _ in 0..100 {
            if !hp.check("a", "act", "x").is_allowed() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!hp.check("a", "act", "x").is_allowed());

        hp.stop();
        watcher.join().unwrap();
        std::fs::remove_file(&path).ok();
    }
}
