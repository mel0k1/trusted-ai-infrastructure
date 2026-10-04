# Trusted AI Infrastructure

[![CI](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml/badge.svg)](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Слой доверия для AI-систем: роутинг моделей, гейты агентов, права доступа, sandbox инструментов и аудит — небольшие компонуемые крейты на Rust с политикой «всё запрещено по умолчанию». Sync и async (tokio) API.

[English](README.md) | Русский

## Архитектура

```
                 Trusted AI Infrastructure
                           │
          ┌────────────────┼────────────────┐
          │                │                │
        Models           Agents           Policy
          │                │                │
     local/API       sandbox/tools     permissions
          │                │                │
          └────────────────┼────────────────┘
                           ↓
                    Audit / Events
```

Каждое действие агента сначала проходит проверку policy, и каждое решение — allow или deny — попадает в аудит-лог с хэш-цепочкой. Ничего не разрешено, пока правило явно этого не разрешит.

## Крейты

| Крейт | Назначение |
|---|---|
| [`tai-core`](crates/tai-core) | общие типы событий |
| [`tai-policy`](crates/tai-policy) | policy engine: правила allow/deny с wildcard, deny важнее allow, default deny |
| [`tai-models`](crates/tai-models) | роутер моделей: sync + async (tokio), один интерфейс для local и API моделей, фолбэк, таймауты |
| [`tai-sandbox`](crates/tai-sandbox) | sandbox инструментов: белый список, таймауты, лимиты вывода и параллелизма |
| [`tai-agents`](crates/tai-agents) | гейт агента: sync и async агенты, действия проходят через policy, результаты пишутся в аудит |
| [`tai-audit`](crates/tai-audit) | JSONL аудит-лог с хэш-цепочкой SHA-256 (защита от подделки) |

## Быстрый старт

```bash
cargo build
cargo test
cargo run --example demo -p tai-agents
```

## Policy engine

Правила сопоставляют `agent` / `action` / `resource` с wildcard `*`. Deny важнее allow; всё, что не подошло ни одному правилу, запрещено.

```rust
use tai_policy::Policy;

let policy = Policy::new()
    .allow("research-*", "tool.call", "web.get:*")
    .allow("*", "model.invoke", "model:*")
    .deny("*", "tool.call", "fs.write:/etc/*");

assert!(policy.check("research-1", "tool.call", "web.get:example.com").is_allowed());
assert!(!policy.check("research-1", "tool.call", "fs.write:/etc/passwd").is_allowed());
```

Политику можно хранить в JSON:

```json
{
  "rules": [
    { "effect": "allow", "agent": "research-*", "action": "tool.call", "resource": "web.get:*" },
    { "effect": "deny",  "agent": "*",          "action": "tool.call", "resource": "fs.write:/etc/*" }
  ]
}
```

## Роутер моделей

Подходит любой OpenAI-совместимый эндпоинт: OpenAI, Ollama (`/v1`), vLLM, llama.cpp. Роутер перебирает модели по порядку, при ошибке переходит к следующей; на каждую попытку можно поставить таймаут.

Sync:

```rust
use std::sync::Arc;
use std::time::Duration;
use tai_models::{CompletionRequest, Echo, OpenAiCompat, Router};

let api = Arc::new(
    OpenAiCompat::new("main", "http://localhost:11434/v1", "qwen2.5:7b")
        .timeout(Duration::from_secs(30)),
);
let fallback = Arc::new(Echo::new("local-echo"));

let router = Router::new()
    .with_timeout(Duration::from_secs(60))
    .register(api)
    .register(fallback);

let answer = router.complete(&CompletionRequest::new("ping")).unwrap();
```

Async на tokio — sync-модели запускаются через `register_sync` в blocking-пуле:

```rust
use std::sync::Arc;
use std::time::Duration;
use tai_models::{AsyncOpenAiCompat, AsyncRouter, CompletionRequest, Echo};

#[tokio::main]
async fn main() {
    let api = Arc::new(
        AsyncOpenAiCompat::new("main", "http://localhost:11434/v1", "qwen2.5:7b")
            .timeout(Duration::from_secs(30)),
    );
    let fallback = Arc::new(Echo::new("local-echo"));

    let router = AsyncRouter::new()
        .with_timeout(Duration::from_secs(60))
        .register(api)
        .register_sync(fallback);

    let answer = router.complete(&CompletionRequest::new("ping")).await.unwrap();
}
```

## Sandbox инструментов

Инструменты белым списком, с лимитами на таймаут, размер вывода и параллелизм; слишком длинный вывод обрезается по границе символов. Свои инструменты реализуют async-трейт `Tool`.

```rust
use std::sync::Arc;
use std::time::Duration;
use tai_sandbox::{EchoTool, Limits, Sandbox};

let sandbox = Sandbox::new(Limits {
    timeout: Duration::from_secs(5),
    max_output: 16 * 1024,
    max_concurrent: 4,
})
.register(Arc::new(EchoTool));

assert_eq!(sandbox.execute("echo", "ping").await.unwrap(), "ping");
assert!(matches!(
    sandbox.execute("fs.write", "/etc").await,
    Err(tai_sandbox::ToolError::NotFound(_))
));
```

## Агенты

Агент связывает роутер, политику, аудит-лог и (для async) sandbox. `call_tool` сначала проверяет `tool.call` на `{tool}:{input}`, затем исполняет инструмент внутри sandbox — запрещённое действие до инструмента не доходит.

```rust
use std::sync::Arc;
use tai_agents::AsyncAgent;
use tai_audit::AuditLog;
use tai_models::{AsyncRouter, Echo};
use tai_policy::Policy;
use tai_sandbox::{EchoTool, Limits, Sandbox};

let agent = AsyncAgent::new(
    "assistant-1",
    Arc::new(AsyncRouter::new().register_sync(Arc::new(Echo::new("echo")))),
    Arc::new(Policy::new()
        .allow("assistant-1", "model.invoke", "model:*")
        .allow("assistant-1", "tool.call", "echo:*")),
    Arc::new(AuditLog::stderr()),
    Arc::new(Sandbox::new(Limits::default()).register(Arc::new(EchoTool))),
);

agent.ask("hello").await.unwrap(); // разрешено, событие в аудите
agent.call_tool("echo", "ping").await.unwrap(); // гейт + sandbox, событие в аудите
agent.call_tool("fs.write", "/etc").await.unwrap_err(); // default deny
```

Для кода без tokio доступен sync `Agent` с тем же гейтом.

## Аудит

Каждая JSONL-строка несёт `prev` и `hash` — SHA-256 от предыдущего хэша и события, якорь — genesis-хэш. Повторное открытие файла продолжает цепочку, поэтому проверка работает и между перезапусками. Любая правка прошлой строки ломает её:

```rust
use tai_audit::AuditLog;

let audit = AuditLog::file("audit.jsonl")?;
audit.log(&Event::now("policy.allow", "assistant-1", "tool.call echo:ping"));

tai_audit::verify("audit.jsonl")?; // Ok(()) — цепочка цела
```

Строка в логе:

```json
{"ts":1728000000,"kind":"policy.allow","actor":"assistant-1","detail":"tool.call echo:ping","prev":"000...0","hash":"9f2c..."}
```

## Дорожная карта

- [x] sandbox для инструментов: белый список с лимитами выполнения
- [x] async API на tokio
- [x] хэш-цепочка в аудит-логе (защита от подделки)
- [ ] стриминг completions
- [ ] горячая перезагрузка политик
- [ ] внешнее якорение цепочки аудита

## Лицензия

Apache-2.0 — см. [LICENSE](LICENSE).
