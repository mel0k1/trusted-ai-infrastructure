# Trusted AI Infrastructure

[![CI](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml/badge.svg)](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Слой доверия для AI-систем: роутинг моделей со стримингом, гейты агентов, права доступа, sandbox инструментов и аудит с защитой от подделки — небольшие компонуемые крейты на Rust с политикой «всё запрещено по умолчанию». Sync и async (tokio) API.

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
| [`tai-policy`](crates/tai-policy) | policy engine: правила allow/deny с wildcard, deny важнее allow, default deny, hot-reload из файла |
| [`tai-models`](crates/tai-models) | роутер моделей: sync + async (tokio), SSE-стриминг, фолбэк, таймауты |
| [`tai-sandbox`](crates/tai-sandbox) | sandbox инструментов: белый список, таймауты, лимиты вывода и параллелизма |
| [`tai-agents`](crates/tai-agents) | гейт агента: sync и async агенты, действия проходят через policy, результаты пишутся в аудит |
| [`tai-audit`](crates/tai-audit) | JSONL аудит-лог с хэш-цепочкой SHA-256 и внешним якорением (файл / HTTP) |

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

### Горячая перезагрузка

`HotPolicy` следит за JSON-файлом и атомарно подменяет живую политику. Битый файл никогда не заменит рабочую политику — ошибка возвращается наружу, старые правила продолжают работать.

```rust
use std::sync::Arc;
use std::time::Duration;
use tai_policy::HotPolicy;

let hot = HotPolicy::new("policy.json")?;
let watcher = hot.spawn_watcher(Duration::from_secs(5));

// всегда свежий снапшот, проверка без блокировки через Arc
let decision = hot.check("agent-1", "tool.call", "web.get:x");

hot.stop();
watcher.join().unwrap();
```

## Роутер моделей

Подходит любой OpenAI-совместимый эндпоинт: OpenAI, Ollama (`/v1`), vLLM, llama.cpp. Роутер перебирает модели по порядку, при ошибке переходит к следующей; на каждую попытку можно поставить таймаут.

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

    // register_sync запускает sync-модели в blocking-пуле
    let router = AsyncRouter::new()
        .with_timeout(Duration::from_secs(60))
        .register(api)
        .register_sync(fallback);

    let answer = router.complete(&CompletionRequest::new("ping")).await.unwrap();
}
```

### Стриминг

`stream` парсит OpenAI SSE и отдаёт дельты в `DeltaSink` (любой `FnMut(&str) + Send`). Фолбэк работает только пока дельты не пошли — если стрим уже начался, ошибка посреди стрима фатальна, а не дублирует вывод на следующей модели.

```rust
use tai_models::DeltaSink;

let mut full = String::new();
let resp = router
    .stream(&CompletionRequest::new("tell me a story"), &mut |d: &str| {
        print!("{d}");
        full.push_str(d);
    })
    .await
    .unwrap();
// resp.text == full
```

Агенты стримят через тот же гейт:

```rust
let text = agent.ask_stream("hello", &mut |d: &str| print!("{d}")).await.unwrap();
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

### Внешнее якорение

Локальную цепочку можно переписать целиком. От этого спасают чекпоинты: каждые N событий голова цепочки публикуется во внешний `Anchor` (append-only файл, HTTP-эндпоинт, SIEM — трейт реализуется под что угодно). Якорь сам сцеплен хэшами, а чекпоинты сверяются с логом по высоте:

```rust
use tai_audit::{AuditLog, FileAnchor};

let anchor = FileAnchor::create("audit.anchor.jsonl");
let audit = AuditLog::file_anchored("audit.jsonl", Box::new(anchor), 100)?;
// каждые 100 событий -> Checkpoint { height, head } уходит в файл якоря

tai_audit::verify_with_anchor("audit.jsonl", "audit.anchor.jsonl")?; // Ok(())
```

Строка чекпоинта:

```json
{"height":200,"head":"fc14...","ts":1791123410,"prev":"c2ef...","hash":"63a9..."}
```

## Дорожная карта

- [x] sandbox для инструментов: белый список с лимитами выполнения
- [x] async API на tokio
- [x] хэш-цепочка в аудит-логе (защита от подделки)
- [x] стриминг completions (SSE)
- [x] горячая перезагрузка политик
- [x] внешнее якорение (файл / HTTP)
- [ ] RFC-3161 таймстампы для чекпоинтов
- [ ] hot-reload политик из удалённых источников

## Лицензия

Apache-2.0 — см. [LICENSE](LICENSE).
