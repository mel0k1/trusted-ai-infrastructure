//! Общие типы Trusted AI Infrastructure.

use serde::Serialize;

/// Событие аудита: единый формат для всех компонентов.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// Unix-время в секундах.
    pub ts: u64,
    /// Тип события: policy.allow, policy.deny, model.invoke и т.д.
    pub kind: String,
    /// Кто вызвал: id агента.
    pub actor: String,
    /// Детали в свободной форме.
    pub detail: String,
}

impl Event {
    pub fn now(kind: &str, actor: &str, detail: impl Into<String>) -> Self {
        Self {
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            kind: kind.to_string(),
            actor: actor.to_string(),
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_has_timestamp() {
        let e = Event::now("test.kind", "agent-1", "hello");
        assert!(e.ts > 0);
        assert_eq!(e.kind, "test.kind");
        assert_eq!(e.actor, "agent-1");
        assert_eq!(e.detail, "hello");
    }
}
