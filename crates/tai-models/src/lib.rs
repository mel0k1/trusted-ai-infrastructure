//! Модели и роутер: единый интерфейс, фолбэк, таймауты; sync и async (tokio).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
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

/// Приёмник дельт стрима; реализован для любых FnMut(&str) + Send.
pub trait DeltaSink: Send {
    fn on_delta(&mut self, delta: &str);
}

impl<F: FnMut(&str) + Send> DeltaSink for F {
    fn on_delta(&mut self, delta: &str) {
        self(delta);
    }
}

#[async_trait]
pub trait AsyncModel: Send + Sync {
    fn id(&self) -> &str;
    async fn complete(&self, req: &CompletionRequest) -> Result<CompletionResponse, ModelError>;

    /// SSE-стрим: дельты в sink, возврат — полный текст.
    /// Дефолт: без дельт, просто complete.
    async fn stream(
        &self,
        req: &CompletionRequest,
        _on_delta: &mut dyn DeltaSink,
    ) -> Result<String, ModelError> {
        let resp = self.complete(req).await?;
        Ok(resp.text)
    }
}

#[async_trait]
impl AsyncModel for Echo {
    fn id(&self) -> &str {
        Model::id(self)
    }

    async fn complete(&self, req: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
        Model::complete(self, req)
    }
}

/// Async-вариант OpenAI-совместимого API на reqwest.
pub struct AsyncOpenAiCompat {
    id: String,
    base_url: String,
    model: String,
    api_key: Option<String>,
    http: reqwest::Client,
}

impl AsyncOpenAiCompat {
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
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("http client"),
        }
    }

    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.http = reqwest::Client::builder()
            .timeout(t)
            .build()
            .expect("http client");
        self
    }
}

#[async_trait]
impl AsyncModel for AsyncOpenAiCompat {
    fn id(&self) -> &str {
        &self.id
    }

    async fn complete(&self, req: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [{ "role": "user", "content": req.prompt }],
            "max_tokens": req.max_tokens.unwrap_or(1024),
        });

        let mut request = self
            .http
            .post(format!("{}/chat/completions", self.base_url))
            .json(&body);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| ModelError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let message = resp.text().await.unwrap_or_default();
            return Err(ModelError::Api {
                status: status.as_u16(),
                message,
            });
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ModelError::Network(e.to_string()))?;

        let text = json["choices"][0]["message"]["content"]
            .as_str()
            .ok_or(ModelError::Api {
                status: status.as_u16(),
                message: "missing choices[0].message.content".into(),
            })?
            .to_string();

        Ok(CompletionResponse {
            model: self.id.clone(),
            text,
        })
    }

    async fn stream(
        &self,
        req: &CompletionRequest,
        on_delta: &mut dyn DeltaSink,
    ) -> Result<String, ModelError> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [{ "role": "user", "content": req.prompt }],
            "max_tokens": req.max_tokens.unwrap_or(1024),
            "stream": true,
        });

        let mut request = self
            .http
            .post(format!("{}/chat/completions", self.base_url))
            .json(&body);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }

        let mut resp = request
            .send()
            .await
            .map_err(|e| ModelError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let message = resp.text().await.unwrap_or_default();
            return Err(ModelError::Api {
                status: status.as_u16(),
                message,
            });
        }

        let mut buf = String::new();
        let mut full = String::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| ModelError::Network(e.to_string()))?
        {
            // JSON обычно ASCII-экранирован, lossy на границе чанка ок
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(pos) = buf.find('\n') {
                let line: String = buf.drain(..=pos).collect();
                if let Some(data) = line.trim().strip_prefix("data:") {
                    let data = data.trim();
                    if data == "[DONE]" {
                        return Ok(full);
                    }
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
                        if let Some(delta) = v["choices"][0]["delta"]["content"].as_str() {
                            if !delta.is_empty() {
                                on_delta.on_delta(delta);
                                full.push_str(delta);
                            }
                        }
                    }
                }
            }
        }
        Ok(full)
    }
}

/// Мост: синхронная модель в async через spawn_blocking.
pub struct SyncToAsync(pub Arc<dyn Model>);

#[async_trait]
impl AsyncModel for SyncToAsync {
    fn id(&self) -> &str {
        self.0.id()
    }

    async fn complete(&self, req: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
        let model = Arc::clone(&self.0);
        let owned = req.clone();
        tokio::task::spawn_blocking(move || model.complete(&owned))
            .await
            .map_err(|e| ModelError::Network(e.to_string()))?
    }
}

/// Async-роутер: перебор моделей с фолбэком и таймаутом на попытку.
pub struct AsyncRouter {
    models: Vec<Arc<dyn AsyncModel>>,
    timeout: Option<Duration>,
}

impl AsyncRouter {
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

    pub fn register(mut self, model: Arc<dyn AsyncModel>) -> Self {
        self.models.push(model);
        self
    }

    pub fn register_sync(self, model: Arc<dyn Model>) -> Self {
        self.register(Arc::new(SyncToAsync(model)))
    }

    pub async fn complete(
        &self,
        req: &CompletionRequest,
    ) -> Result<CompletionResponse, ModelError> {
        if self.models.is_empty() {
            return Err(ModelError::Empty);
        }
        let mut last: Option<ModelError> = None;
        for model in &self.models {
            let attempt = match self.timeout {
                Some(t) => match tokio::time::timeout(t, model.complete(req)).await {
                    Ok(r) => r,
                    Err(_) => Err(ModelError::Timeout(t)),
                },
                None => model.complete(req).await,
            };
            match attempt {
                Ok(resp) => return Ok(resp),
                Err(e) => last = Some(e),
            }
        }
        Err(last.expect("models is not empty"))
    }

    /// Стрим с фолбэком: переход к следующей модели только пока дельты не пошли.
    pub async fn stream(
        &self,
        req: &CompletionRequest,
        on_delta: &mut dyn DeltaSink,
    ) -> Result<CompletionResponse, ModelError> {
        if self.models.is_empty() {
            return Err(ModelError::Empty);
        }
        let mut last: Option<ModelError> = None;
        for model in &self.models {
            let emitted = std::sync::atomic::AtomicBool::new(false);
            let mut wrapped = |d: &str| {
                emitted.store(true, std::sync::atomic::Ordering::Relaxed);
                on_delta.on_delta(d);
            };
            match model.stream(req, &mut wrapped).await {
                Ok(text) => {
                    return Ok(CompletionResponse {
                        model: model.id().to_string(),
                        text,
                    });
                }
                Err(e) => {
                    if emitted.load(std::sync::atomic::Ordering::Relaxed) {
                        return Err(e);
                    }
                    last = Some(e);
                }
            }
        }
        Err(last.expect("models is not empty"))
    }
}

impl Default for AsyncRouter {
    fn default() -> Self {
        Self::new()
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

    struct AsyncFail;

    #[async_trait]
    impl AsyncModel for AsyncFail {
        fn id(&self) -> &str {
            "failing"
        }

        async fn complete(&self, _: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
            Err(ModelError::Network("down".into()))
        }
    }

    struct AsyncSlow;

    #[async_trait]
    impl AsyncModel for AsyncSlow {
        fn id(&self) -> &str {
            "slow"
        }

        async fn complete(&self, _: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok(CompletionResponse {
                model: "slow".into(),
                text: "done".into(),
            })
        }
    }

    #[tokio::test]
    async fn async_router_falls_back_to_sync_model() {
        let router = AsyncRouter::new()
            .register(Arc::new(AsyncFail))
            .register_sync(Arc::new(Echo::new("echo")));
        let resp = router
            .complete(&CompletionRequest::new("hi"))
            .await
            .unwrap();
        assert_eq!(resp.model, "echo");
        assert_eq!(resp.text, "hi");
    }

    #[tokio::test]
    async fn async_router_applies_timeout() {
        let router = AsyncRouter::new()
            .with_timeout(Duration::from_millis(50))
            .register(Arc::new(AsyncSlow));
        assert!(matches!(
            router.complete(&CompletionRequest::new("hi")).await,
            Err(ModelError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn async_empty_router_is_error() {
        let router = AsyncRouter::new();
        assert!(matches!(
            router.complete(&CompletionRequest::new("hi")).await,
            Err(ModelError::Empty)
        ));
    }

    #[tokio::test]
    async fn async_openai_network_error() {
        let m = AsyncOpenAiCompat::new("main", "http://127.0.0.1:1/v1", "test-model");
        let err = m.complete(&CompletionRequest::new("hi")).await.unwrap_err();
        assert!(matches!(err, ModelError::Network(_)));
    }

    struct EmitThenFail;

    #[async_trait]
    impl AsyncModel for EmitThenFail {
        fn id(&self) -> &str {
            "emit-fail"
        }

        async fn complete(&self, _: &CompletionRequest) -> Result<CompletionResponse, ModelError> {
            Err(ModelError::Network("down".into()))
        }

        async fn stream(
            &self,
            _: &CompletionRequest,
            on_delta: &mut dyn DeltaSink,
        ) -> Result<String, ModelError> {
            on_delta.on_delta("part");
            Err(ModelError::Network("mid-stream".into()))
        }
    }

    #[tokio::test]
    async fn stream_reads_sse_deltas() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let body = "data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n\
                        data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n\
                        data: [DONE]\n\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });

        let m = AsyncOpenAiCompat::new("main", format!("http://{addr}/v1"), "m");
        let mut seen = String::new();
        let text = m
            .stream(&CompletionRequest::new("hi"), &mut |d: &str| {
                seen.push_str(d)
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(text, "hello");
        assert_eq!(seen, "hello");
    }

    #[tokio::test]
    async fn stream_falls_back_before_first_delta() {
        let router = AsyncRouter::new()
            .register(Arc::new(AsyncFail))
            .register_sync(Arc::new(Echo::new("echo")));
        let mut seen = String::new();
        let resp = router
            .stream(&CompletionRequest::new("hi"), &mut |d: &str| {
                seen.push_str(d)
            })
            .await
            .unwrap();
        assert_eq!(resp.model, "echo");
        assert_eq!(resp.text, "hi");
        assert!(seen.is_empty());
    }

    #[tokio::test]
    async fn stream_error_after_deltas_is_fatal() {
        let router = AsyncRouter::new()
            .register(Arc::new(EmitThenFail))
            .register_sync(Arc::new(Echo::new("echo")));
        let mut seen = String::new();
        let err = router
            .stream(&CompletionRequest::new("hi"), &mut |d: &str| {
                seen.push_str(d)
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ModelError::Network(_)));
        assert_eq!(seen, "part");
    }
}
