# Trusted AI Infrastructure

[![CI](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml/badge.svg)](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Trust layer for AI systems. Model routing, agent gates, permissions and audit — small composable Rust crates with a deny-by-default posture.

English | [Русский](README.ru.md)

## Architecture

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

Every agent action goes through a policy check first, and every decision — allow or deny — lands in the audit log. Nothing is allowed unless a rule says so.

## Crates

| Crate | What it does |
|---|---|
| [`tai-core`](crates/tai-core) | shared event types |
| [`tai-policy`](crates/tai-policy) | policy engine: allow/deny rules with wildcards, deny overrides, default deny |
| [`tai-models`](crates/tai-models) | model router: one interface for local and API models, fallback, timeouts |
| [`tai-agents`](crates/tai-agents) | agent gate: actions pass policy, results are audited |
| [`tai-audit`](crates/tai-audit) | JSONL audit log: file, stderr or any writer |

## Quick start

```bash
cargo build
cargo test
cargo run --example demo -p tai-agents
```

## Policy engine

Rules match `agent` / `action` / `resource` with `*` wildcards. Deny wins over allow; anything unmatched is denied.

```rust
use tai_policy::Policy;

let policy = Policy::new()
    .allow("research-*", "tool.call", "web.get:*")
    .allow("*", "model.invoke", "model:*")
    .deny("*", "tool.call", "fs.write:/etc/*");

assert!(policy.check("research-1", "tool.call", "web.get:example.com").is_allowed());
assert!(!policy.check("research-1", "tool.call", "fs.write:/etc/passwd").is_allowed());
```

Policies can be stored as JSON:

```json
{
  "rules": [
    { "effect": "allow", "agent": "research-*", "action": "tool.call", "resource": "web.get:*" },
    { "effect": "deny",  "agent": "*",          "action": "tool.call", "resource": "fs.write:/etc/*" }
  ]
}
```

## Model router

Any OpenAI-compatible endpoint works: OpenAI, Ollama (`/v1`), vLLM, llama.cpp. The router tries models in order and falls back on failure; an optional timeout guards each attempt.

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

## Agents

An agent binds a router, a policy and an audit log. Every action is gated and audited:

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

agent.ask("hello").unwrap(); // allowed, audited
agent.ensure_allowed("tool.call", "fs.write:/etc").unwrap_err(); // denied, audited
```

Audit output is JSONL — one event per line:

```json
{"ts":1728000000,"kind":"policy.deny","actor":"assistant-1","detail":"tool.call fs.write:/etc default deny"}
```

## Roadmap

- [ ] tool sandbox: whitelisted tools with execution limits
- [ ] hash-chained audit log (tamper evidence)
- [ ] streaming completions
- [ ] async API on tokio
- [ ] policy hot-reload

## License

Apache-2.0 — see [LICENSE](LICENSE).
