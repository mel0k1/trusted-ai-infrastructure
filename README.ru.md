# Trusted AI Infrastructure

[![CI](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml/badge.svg)](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Слой доверия для AI-систем: роутинг моделей, гейты агентов, права доступа и аудит — небольшие компонуемые крейты на Rust с политикой «всё запрещено по умолчанию».

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

Каждое действие агента сначала проходит проверку policy, и каждое решение — allow или deny — попадает в аудит-лог. Ничего не разрешено, пока правило явно этого не разрешит.

## Крейты

| Крейт | Назначение |
|---|---|
| [`tai-core`](crates/tai-core) | общие типы событий |
| [`tai-policy`](crates/tai-policy) | policy engine: правила allow/deny с wildcard, deny важнее allow, default deny |
| [`tai-models`](crates/tai-models) | роутер моделей: один интерфейс для local и API моделей, фолбэк, таймауты |
| [`tai-agents`](crates/tai-agents) | гейт агента: действия проходят через policy, результаты пишутся в аудит |
| [`tai-audit`](crates/tai-audit) | JSONL аудит-лог: файл, stderr или любой writer |

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

## Агенты

Агент связывает роутер, политику и аудит-лог. Каждое действие проходит гейт и пишется в аудит:

```rust
use std::sync::Arc;
use tai_agents::Agent;
use tai_audit::AuditLog;
use tai_models::{Echo, Router};
use tai_policy::Policy;

let agent = Agent::new(
    "assistant-1",
    Arc::new(Router::new().register(Arc::new(Echo::new("echo")))),
    Arc::new(Policy::new().allow("assistant-1", "model.invoke", "model:*")),
    Arc::new(AuditLog::stderr()),
);

agent.ask("hello").unwrap(); // разрешено, событие в аудите
agent.ensure_allowed("tool.call", "fs.write:/etc").unwrap_err(); // запрещено, событие в аудите
```

Аудит — это JSONL: одно событие на строку:

```json
{"ts":1728000000,"kind":"policy.deny","actor":"assistant-1","detail":"tool.call fs.write:/etc default deny"}
```

## Дорожная карта

- [ ] sandbox для инструментов: белый список с лимитами выполнения
- [ ] хэш-цепочка в аудит-логе (защита от подделки)
- [ ] стриминг completions
- [ ] async API на tokio
- [ ] горячая перезагрузка политик

## Лицензия

Apache-2.0 — см. [LICENSE](LICENSE).
