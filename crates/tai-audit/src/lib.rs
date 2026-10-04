//! Аудит: JSONL с хэш-цепочкой SHA-256 и внешним якорением;
//! запись в файл, stderr или любой writer.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tai_core::Event;
use thiserror::Error;

mod rfc3161;

pub use rfc3161::{verify_tsr, verify_tsr_dir, Rfc3161Anchor, TsaError, TstInfo};

/// Хэш первой записи в цепочке.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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
    #[error("anchor: {0}")]
    Anchor(String),
}

/// Строка лога: событие + prev/hash для защиты от подделки.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedEvent {
    #[serde(flatten)]
    pub event: Event,
    pub prev: String,
    pub hash: String,
}

/// Контрольная точка: голова цепочки, зафиксированная во внешнем хранилище.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: usize,
    pub head: String,
    pub ts: u64,
    pub prev: String,
    pub hash: String,
}

impl Checkpoint {
    pub fn new(height: usize, head: impl Into<String>, prev: impl Into<String>) -> Self {
        let head = head.into();
        let prev = prev.into();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let hash = checkpoint_hash(&prev, height, &head, ts);
        Self {
            height,
            head,
            ts,
            prev,
            hash,
        }
    }
}

fn checkpoint_hash(prev: &str, height: usize, head: &str, ts: u64) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(height.to_string().as_bytes());
    h.update(head.as_bytes());
    h.update(ts.to_string().as_bytes());
    hex::encode(h.finalize())
}

/// Куда-нибудь наружу: получает контрольную точку цепочки.
pub trait Anchor: Send + Sync {
    fn anchor(&self, cp: &Checkpoint) -> Result<(), AuditError>;
}

/// Append-only файл чекпоинтов; хранит их как есть, цепочку ведёт AuditLog.
pub struct FileAnchor {
    path: PathBuf,
}

impl FileAnchor {
    pub fn create(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl Anchor for FileAnchor {
    fn anchor(&self, cp: &Checkpoint) -> Result<(), AuditError> {
        let line = serde_json::to_string(cp).map_err(|e| AuditError::Anchor(e.to_string()))?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.flush()?;
        Ok(())
    }
}

/// POST чекпоинта в HTTP-эндпоинт (внешний тамбстон, сервис или SIEM).
pub struct HttpAnchor {
    url: String,
    http: ureq::Agent,
}

impl HttpAnchor {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            http: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(5))
                .build(),
        }
    }
}

impl Anchor for HttpAnchor {
    fn anchor(&self, cp: &Checkpoint) -> Result<(), AuditError> {
        let resp = self
            .http
            .post(&self.url)
            .send_json(cp)
            .map_err(|e| match e {
                ureq::Error::Status(code, r) => AuditError::Anchor(format!(
                    "status {code}: {}",
                    r.into_string().unwrap_or_default()
                )),
                ureq::Error::Transport(t) => AuditError::Anchor(t.to_string()),
            })?;
        if resp.status() >= 300 {
            return Err(AuditError::Anchor(format!("status {}", resp.status())));
        }
        Ok(())
    }
}

struct Inner {
    sink: Box<dyn Write + Send>,
    prev: String,
    height: usize,
    cp_prev: String,
    anchor: Option<Box<dyn Anchor>>,
    every: usize,
}

pub struct AuditLog {
    inner: Mutex<Inner>,
}

impl AuditLog {
    pub fn new(sink: Box<dyn Write + Send>) -> Self {
        Self::with_parts(sink, GENESIS.to_string(), None, 0)
    }

    fn with_parts(
        sink: Box<dyn Write + Send>,
        prev: String,
        anchor: Option<Box<dyn Anchor>>,
        every: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner {
                sink,
                prev,
                height: 0,
                cp_prev: GENESIS.to_string(),
                anchor,
                every,
            }),
        }
    }

    pub fn stderr() -> Self {
        Self::new(Box::new(std::io::stderr()))
    }

    /// Открывает файл на дозапись и продолжает цепочку с последнего хэша.
    pub fn file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let prev = last_hash(&path).unwrap_or_else(|| GENESIS.to_string());
        let file: File = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self::with_parts(Box::new(file), prev, None, 0))
    }

    /// Как file(), плюс якорение: каждые every событий контрольная точка
    /// уходит во внешний Anchor.
    pub fn file_anchored(
        path: impl AsRef<Path>,
        anchor: Box<dyn Anchor>,
        every: usize,
    ) -> std::io::Result<Self> {
        let prev = last_hash(&path).unwrap_or_else(|| GENESIS.to_string());
        let file: File = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self::with_parts(Box::new(file), prev, Some(anchor), every))
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
        inner.height += 1;

        // якорим каждые every событий
        let due =
            inner.anchor.is_some() && inner.every > 0 && inner.height.is_multiple_of(inner.every);
        if !due {
            return;
        }
        let cp = Checkpoint::new(inner.height, inner.prev.clone(), inner.cp_prev.clone());
        let anchor = inner.anchor.as_ref().expect("checked above");
        match anchor.anchor(&cp) {
            Ok(()) => inner.cp_prev = cp.hash,
            // сбой якорения виден в самом логе; цепочка чекпоинтов не двигается
            Err(e) => {
                let ev = Event::now("anchor.error", "audit", e.to_string());
                let ev_json = serde_json::to_string(&ev).expect("event serializes");
                let h2 = chain_hash(&inner.prev, &ev_json);
                let line = serde_json::to_string(&ChainedEvent {
                    event: ev,
                    prev: inner.prev.clone(),
                    hash: h2.clone(),
                })
                .expect("chained serializes");
                let _ = writeln!(inner.sink, "{line}");
                let _ = inner.sink.flush();
                inner.prev = h2;
                inner.height += 1;
            }
        }
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

/// verify + сверка внешних чекпоинтов с головой лога по высоте.
pub fn verify_with_anchor(
    log_path: impl AsRef<Path>,
    anchor_path: impl AsRef<Path>,
) -> Result<(), AuditError> {
    verify(&log_path)?;

    let content = std::fs::read_to_string(log_path)?;
    let mut heads = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let c: ChainedEvent = serde_json::from_str(line).map_err(|source| AuditError::Json {
            line: i + 1,
            source,
        })?;
        heads.push(c.hash);
    }

    let anchors = std::fs::read_to_string(anchor_path)?;
    let mut prev = GENESIS.to_string();
    for (i, line) in anchors.lines().enumerate() {
        let cp: Checkpoint = serde_json::from_str(line).map_err(|source| AuditError::Json {
            line: i + 1,
            source,
        })?;
        if cp.prev != prev || cp.hash != checkpoint_hash(&cp.prev, cp.height, &cp.head, cp.ts) {
            return Err(AuditError::Broken(i + 1));
        }
        if cp.height == 0 || cp.height > heads.len() || heads[cp.height - 1] != cp.head {
            return Err(AuditError::Broken(i + 1));
        }
        prev = cp.hash;
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
    use serde_json::json;
    use std::io::Read;
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

    #[test]
    fn anchored_log_verifies_and_detects_tamper() {
        let lpath = temp_path("anchored-log");
        let apath = temp_path("anchored-cp");
        let _ = std::fs::remove_file(&lpath);
        let _ = std::fs::remove_file(&apath);
        {
            let anchor = FileAnchor::create(&apath);
            let log = AuditLog::file_anchored(&lpath, Box::new(anchor), 2).unwrap();
            for i in 0..6 {
                log.log(&Event::now("k", "x", i.to_string()));
            }
        }
        assert!(verify(&lpath).is_ok());
        assert!(verify_with_anchor(&lpath, &apath).is_ok());

        // чекпоинты: высоты 2, 4, 6
        let anchors = std::fs::read_to_string(&apath).unwrap();
        assert_eq!(anchors.lines().count(), 3);

        // подмена головы в чекпоинте ловится
        let mut lines: Vec<serde_json::Value> = anchors
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        lines[0]["head"] = json!("ffffffff");
        let rewritten: Vec<String> = lines.iter().map(|v| v.to_string()).collect();
        std::fs::write(&apath, rewritten.join("\n")).unwrap();
        assert!(matches!(
            verify_with_anchor(&lpath, &apath),
            Err(AuditError::Broken(1))
        ));

        let _ = std::fs::remove_file(&lpath);
        let _ = std::fs::remove_file(&apath);
    }

    #[test]
    fn http_anchor_posts_checkpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            // читаем до конца тела по Content-Length: тело может прийти отдельным сегментом
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = sock.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                let cl: usize = headers
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse().unwrap())
                    .unwrap_or(0);
                if buf.len() >= pos + 4 + cl {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf).to_string();
            assert!(req.starts_with("POST /anchor "));
            assert!(req.contains("\"height\":3"));
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });

        let anchor = HttpAnchor::new(format!("http://{addr}/anchor"));
        let cp = Checkpoint::new(3, "abc123", GENESIS);
        anchor.anchor(&cp).unwrap();
        handle.join().unwrap();
    }
}
