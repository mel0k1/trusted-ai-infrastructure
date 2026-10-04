//! Аудит: JSONL с хэш-цепочкой SHA-256; запись в файл, stderr или любой writer.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tai_core::Event;
use thiserror::Error;

/// Хэш первой записи в цепочке.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json at line {line}: {source}")]
    Json {
        line: usize,
        source: serde_json::Error,
    },
    #[error("chain broken at line {0}")]
    Broken(usize),
}

/// Строка лога: событие + prev/hash для защиты от подделки.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedEvent {
    #[serde(flatten)]
    pub event: Event,
    pub prev: String,
    pub hash: String,
}

struct Inner {
    sink: Box<dyn Write + Send>,
    prev: String,
}

pub struct AuditLog {
    inner: Mutex<Inner>,
}

impl AuditLog {
    pub fn new(sink: Box<dyn Write + Send>) -> Self {
        Self::with_prev(sink, GENESIS.to_string())
    }

    fn with_prev(sink: Box<dyn Write + Send>, prev: String) -> Self {
        Self {
            inner: Mutex::new(Inner { sink, prev }),
        }
    }

    pub fn stderr() -> Self {
        Self::new(Box::new(std::io::stderr()))
    }

    /// Открывает файл на дозапись и продолжает цепочку с последнего хэша.
    pub fn file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let prev = last_hash(&path).unwrap_or_else(|| GENESIS.to_string());
        let file: File = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self::with_prev(Box::new(file), prev))
    }

    /// hash = sha256(prev + event) — подмена любой строки ломает цепочку.
    pub fn log(&self, event: &Event) {
        let mut inner = self.inner.lock().expect("audit lock");
        let event_json = serde_json::to_string(event).expect("event serializes");
        let hash = chain_hash(&inner.prev, &event_json);
        let chained = ChainedEvent {
            event: event.clone(),
            prev: inner.prev.clone(),
            hash: hash.clone(),
        };
        let line = serde_json::to_string(&chained).expect("chained serializes");
        let _ = writeln!(inner.sink, "{line}");
        let _ = inner.sink.flush();
        inner.prev = hash;
    }
}

/// Проверяет файл: формат каждой строки и целостность цепочки.
pub fn verify(path: impl AsRef<Path>) -> Result<(), AuditError> {
    let content = std::fs::read_to_string(path)?;
    let mut prev = GENESIS.to_string();
    for (i, line) in content.lines().enumerate() {
        let chained: ChainedEvent =
            serde_json::from_str(line).map_err(|source| AuditError::Json {
                line: i + 1,
                source,
            })?;
        let event_json = serde_json::to_string(&chained.event).expect("event serializes");
        if chained.prev != prev || chain_hash(&prev, &event_json) != chained.hash {
            return Err(AuditError::Broken(i + 1));
        }
        prev = chained.hash;
    }
    Ok(())
}

fn chain_hash(prev: &str, event_json: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(event_json.as_bytes());
    hex::encode(h.finalize())
}

fn last_hash(path: impl AsRef<Path>) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    content
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str::<ChainedEvent>(l).ok().map(|c| c.hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tai-audit-{}-{tag}.jsonl", std::process::id()))
    }

    #[test]
    fn in_memory_lines_are_chained() {
        let buf = SharedBuf::default();
        let probe = buf.clone();
        let log = AuditLog::new(Box::new(buf));

        log.log(&Event::now("policy.allow", "agent-1", "a"));
        log.log(&Event::now("policy.deny", "agent-2", "b"));

        let out = String::from_utf8(probe.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: ChainedEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.prev, GENESIS);
        assert!(first.hash.chars().all(|c| c.is_ascii_hexdigit()));

        let second: ChainedEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second.prev, first.hash);
        assert_ne!(first.hash, second.hash);
    }

    #[test]
    fn file_chain_verifies() {
        let path = temp_path("ok");
        let _ = std::fs::remove_file(&path);
        {
            let log = AuditLog::file(&path).unwrap();
            log.log(&Event::now("a", "x", "1"));
            log.log(&Event::now("b", "x", "2"));
        }
        assert!(verify(&path).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_line_is_detected() {
        let path = temp_path("tamper");
        let _ = std::fs::remove_file(&path);
        {
            let log = AuditLog::file(&path).unwrap();
            log.log(&Event::now("a", "x", "1"));
            log.log(&Event::now("b", "x", "2"));
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("\"detail\":\"1\"", "\"detail\":\"HACKED\"");
        assert_ne!(content, tampered);
        std::fs::write(&path, tampered).unwrap();
        assert!(matches!(verify(&path), Err(AuditError::Broken(1))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn chain_continues_after_reopen() {
        let path = temp_path("reopen");
        let _ = std::fs::remove_file(&path);
        {
            let log = AuditLog::file(&path).unwrap();
            log.log(&Event::now("a", "x", "1"));
        }
        {
            let log = AuditLog::file(&path).unwrap();
            log.log(&Event::now("b", "x", "2"));
        }
        assert!(verify(&path).is_ok());
        let _ = std::fs::remove_file(&path);
    }
}
