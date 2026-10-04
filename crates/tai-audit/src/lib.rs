//! Аудит: JSONL-события в файл, stderr или любой writer.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use tai_core::Event;

pub struct AuditLog {
    // writer под мьютексом: события разных агентов не перемешаются
    sink: Mutex<Box<dyn Write + Send>>,
}

impl AuditLog {
    pub fn new(sink: Box<dyn Write + Send>) -> Self {
        Self {
            sink: Mutex::new(sink),
        }
    }

    pub fn stderr() -> Self {
        Self::new(Box::new(std::io::stderr()))
    }

    pub fn file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file: File = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self::new(Box::new(file)))
    }

    /// Пишет событие одной JSONL-строкой.
    pub fn log(&self, event: &Event) {
        let line = serde_json::to_string(event).expect("event serializes");
        if let Ok(mut sink) = self.sink.lock() {
            let _ = writeln!(sink, "{line}");
            let _ = sink.flush();
        }
    }
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

    #[test]
    fn writes_valid_jsonl() {
        let buf = SharedBuf::default();
        let probe = buf.clone();
        let log = AuditLog::new(Box::new(buf));

        log.log(&Event::now(
            "policy.allow",
            "agent-1",
            "tool.call web.get:*",
        ));
        log.log(&Event::now("policy.deny", "agent-2", "fs.write denied"));

        let out = String::from_utf8(probe.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v["ts"].is_u64());
            assert!(v["kind"].is_string());
        }
        assert!(lines[0].contains("policy.allow"));
    }
}
