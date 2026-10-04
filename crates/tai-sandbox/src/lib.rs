//! Sandbox инструментов: белый список, таймаут, лимиты вывода и параллелизма.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::Semaphore;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("tool not found: {0}")]
    NotFound(String),
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("busy: concurrency limit reached")]
    Busy,
    #[error("failed: {0}")]
    Failed(String),
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    async fn run(&self, input: &str) -> Result<String, ToolError>;
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub timeout: Duration,
    pub max_output: usize,
    pub max_concurrent: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_output: 64 * 1024,
            max_concurrent: 8,
        }
    }
}

pub struct Sandbox {
    tools: HashMap<String, Arc<dyn Tool>>,
    limits: Limits,
    permits: Arc<Semaphore>,
}

impl Sandbox {
    pub fn new(limits: Limits) -> Self {
        let permits = Arc::new(Semaphore::new(limits.max_concurrent));
        Self {
            tools: HashMap::new(),
            limits,
            permits,
        }
    }

    pub fn register(mut self, tool: Arc<dyn Tool>) -> Self {
        self.tools.insert(tool.name().to_string(), tool);
        self
    }

    pub fn tools(&self) -> Vec<&str> {
        self.tools.keys().map(|s| s.as_str()).collect()
    }

    /// Порядок защиты: белый список -> лимит параллелизма -> таймаут -> лимит вывода.
    pub async fn execute(&self, name: &str, input: &str) -> Result<String, ToolError> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| ToolError::NotFound(name.into()))?;
        // permit живёт до конца функции, освобождается автоматически
        let _permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ToolError::Busy)?;
        let out = tokio::time::timeout(self.limits.timeout, tool.run(input))
            .await
            .map_err(|_| ToolError::Timeout(self.limits.timeout))??;
        Ok(truncate(out, self.limits.max_output))
    }
}

fn truncate(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    // граница символа, чтобы не разрезать UTF-8
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

pub struct EchoTool;

#[async_trait]
impl Tool for EchoTool {
    fn name(&self) -> &str {
        "echo"
    }

    async fn run(&self, input: &str) -> Result<String, ToolError> {
        Ok(input.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Slow;

    #[async_trait]
    impl Tool for Slow {
        fn name(&self) -> &str {
            "slow"
        }

        async fn run(&self, _: &str) -> Result<String, ToolError> {
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok("done".into())
        }
    }

    struct Big;

    #[async_trait]
    impl Tool for Big {
        fn name(&self) -> &str {
            "big"
        }

        async fn run(&self, _: &str) -> Result<String, ToolError> {
            Ok("x".repeat(1000))
        }
    }

    struct Boom;

    #[async_trait]
    impl Tool for Boom {
        fn name(&self) -> &str {
            "boom"
        }

        async fn run(&self, _: &str) -> Result<String, ToolError> {
            Err(ToolError::Failed("no".into()))
        }
    }

    #[tokio::test]
    async fn runs_whitelisted_tool() {
        let s = Sandbox::new(Limits::default()).register(Arc::new(EchoTool));
        assert_eq!(s.execute("echo", "ping").await.unwrap(), "ping");
    }

    #[tokio::test]
    async fn unknown_tool_is_not_found() {
        let s = Sandbox::new(Limits::default()).register(Arc::new(EchoTool));
        assert!(matches!(
            s.execute("nope", "x").await,
            Err(ToolError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn timeout_kills_slow_tool() {
        let s = Sandbox::new(Limits {
            timeout: Duration::from_millis(50),
            ..Default::default()
        })
        .register(Arc::new(Slow));
        assert!(matches!(
            s.execute("slow", "x").await,
            Err(ToolError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn output_is_truncated() {
        let s = Sandbox::new(Limits {
            max_output: 10,
            ..Default::default()
        })
        .register(Arc::new(Big));
        assert_eq!(s.execute("big", "x").await.unwrap().len(), 10);
    }

    #[tokio::test]
    async fn tool_errors_pass_through() {
        let s = Sandbox::new(Limits::default()).register(Arc::new(Boom));
        assert!(matches!(
            s.execute("boom", "x").await,
            Err(ToolError::Failed(_))
        ));
    }

    #[tokio::test]
    async fn concurrency_limit_returns_busy() {
        let s = Arc::new(
            Sandbox::new(Limits {
                max_concurrent: 1,
                timeout: Duration::from_secs(5),
                ..Default::default()
            })
            .register(Arc::new(Slow)),
        );
        let a = s.clone();
        let b = s.clone();
        let (r1, r2) = tokio::join!(a.execute("slow", "x"), b.execute("slow", "x"));
        let results = [r1, r2];
        let oks = results.iter().filter(|r| r.is_ok()).count();
        let busy = results
            .iter()
            .filter(|r| matches!(r, Err(ToolError::Busy)))
            .count();
        assert_eq!((oks, busy), (1, 1));
    }
}
