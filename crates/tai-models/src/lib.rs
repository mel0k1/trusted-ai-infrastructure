//! Модели и роутер: единый интерфейс, фолбэк, таймауты.

use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("api {status}: {message}")]
    Api { status: u16, message: String },
    #[error("network: {0}")]
    Network(String),
    #[error("no models registered")]
    Empty,
}

#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub prompt: String,
    pub max_tokens: Option<u32>,
}

impl CompletionRequest {
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            max_tokens: None,
        }
    }

    pub fn with_max_tokens(mut self, n: u32) -> Self {
        self.max_tokens = Some(n);
        self
    }
}

#[derive(Debug, Clone)]
pub struct CompletionResponse {
    pub model: String,
    pub text: String,
}

pub trait Model: Send + Sync {
    fn id(&self) -> &str;
    fn complete(&self, req: &CompletionRequest) -> Result<CompletionResponse, ModelError>;
}

/// Заглушка для тестов и локальной разработки: возвращает prompt как есть.
pub struct Echo {
    id: String,
}

impl Echo {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

impl Model for Echo {
    fn id(&self) -> &str {
        &self.id
    }

    fn complete(&self, req: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
        Ok(CompletionResponse {
            model: self.id.clone(),
            text: req.prompt.clone(),
        })
    }
}

/// Любой OpenAI-совместимый API: OpenAI, Ollama (`/v1`), vLLM, llama.cpp.
pub struct OpenAiCompat {
    id: String,
    base_url: String,
    model: String,
    api_key: Option<String>,
    http: ureq::Agent,
}

impl OpenAiCompat {
    pub fn new(
        id: impl Into<String>,
        base_url: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            model: model.into(),
            api_key: None,
            http: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }

    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.http = ureq::AgentBuilder::new().timeout(t).build();
        self
    }
}

impl Model for OpenAiCompat {
    fn id(&self) -> &str {
        &self.id
    }

    fn complete(&self, req: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [{ "role": "user", "content": req.prompt }],
            "max_tokens": req.max_tokens.unwrap_or(1024),
        });

        let mut request = self
            .http
            .post(&format!("{}/chat/completions", self.base_url))
            .set("Content-Type", "application/json");
        if let Some(key) = &self.api_key {
            request = request.set("Authorization", &format!("Bearer {key}"));
        }

        let resp = request.send_json(body).map_err(|e| match e {
            ureq::Error::Status(code, resp) => ModelError::Api {
                status: code,
                message: resp.into_string().unwrap_or_default(),
            },
            ureq::Error::Transport(t) => ModelError::Network(t.to_string()),
        })?;

        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| ModelError::Network(e.to_string()))?;

        let text = json["choices"][0]["message"]["content"]
            .as_str()
            .ok_or(ModelError::Api {
                status: 200,
                message: "missing choices[0].message.content".into(),
            })?
            .to_string();

        Ok(CompletionResponse {
            model: self.id.clone(),
            text,
        })
    }
}

/// Пытает модели по порядку; на ошибке переходит к следующей.
pub struct Router {
    models: Vec<Arc<dyn Model>>,
    timeout: Option<Duration>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            models: Vec::new(),
            timeout: None,
        }
    }

    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    pub fn register(mut self, model: Arc<dyn Model>) -> Self {
        self.models.push(model);
        self
    }

    pub fn models(&self) -> &[Arc<dyn Model>] {
        &self.models
    }

    pub fn complete(&self, req: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
        if self.models.is_empty() {
            return Err(ModelError::Empty);
        }
        let mut last: Option<ModelError> = None;
        for model in &self.models {
            let attempt = match self.timeout {
                Some(t) => {
                    let model = Arc::clone(model);
                    let owned = req.clone();
                    with_timeout(t, move || model.complete(&owned))
                }
                None => model.complete(req),
            };
            match attempt {
                Ok(resp) => return Ok(resp),
                Err(e) => last = Some(e),
            }
        }
        Err(last.expect("models is not empty"))
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Синхронный таймаут: попытка уходит в отдельный поток.
fn with_timeout<F>(t: Duration, f: F) -> Result<CompletionResponse, ModelError>
where
    F: FnOnce() -> Result<CompletionResponse, ModelError> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(t) {
        Ok(res) => res,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(ModelError::Timeout(t)),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(ModelError::Network("model thread panicked".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Failing;

    impl Model for Failing {
        fn id(&self) -> &str {
            "failing"
        }

        fn complete(&self, _: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
            Err(ModelError::Network("down".into()))
        }
    }

    struct Slow;

    impl Model for Slow {
        fn id(&self) -> &str {
            "slow"
        }

        fn complete(&self, _: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
            std::thread::sleep(Duration::from_millis(400));
            Ok(CompletionResponse {
                model: "slow".into(),
                text: "done".into(),
            })
        }
    }

    #[test]
    fn router_falls_back_to_next_model() {
        let router = Router::new()
            .register(Arc::new(Failing))
            .register(Arc::new(Echo::new("echo")));
        let resp = router.complete(&CompletionRequest::new("hi")).unwrap();
        assert_eq!(resp.model, "echo");
        assert_eq!(resp.text, "hi");
    }

    #[test]
    fn router_applies_timeout() {
        let router = Router::new()
            .with_timeout(Duration::from_millis(50))
            .register(Arc::new(Slow));
        assert!(matches!(
            router.complete(&CompletionRequest::new("hi")),
            Err(ModelError::Timeout(_))
        ));
    }

    #[test]
    fn slow_model_passes_under_timeout() {
        let router = Router::new()
            .with_timeout(Duration::from_secs(5))
            .register(Arc::new(Slow));
        assert_eq!(
            router.complete(&CompletionRequest::new("hi")).unwrap().text,
            "done"
        );
    }

    #[test]
    fn empty_router_is_error() {
        let router = Router::new();
        assert!(matches!(
            router.complete(&CompletionRequest::new("hi")),
            Err(ModelError::Empty)
        ));
    }

    #[test]
    fn openai_compat_builds_request_path() {
        let m = OpenAiCompat::new("main", "http://127.0.0.1:1/v1/", "test-model");
        assert_eq!(m.base_url, "http://127.0.0.1:1/v1");
        // сетевой запрос упадёт транспортной ошибкой, а не паникой
        let err = m.complete(&CompletionRequest::new("hi")).unwrap_err();
        assert!(matches!(err, ModelError::Network(_)));
    }
}
