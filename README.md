# Trusted AI Infrastructure

[![CI](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml/badge.svg)](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Trust layer for AI systems. Model routing, agent gates, permissions, tool sandbox and audit — small composable Rust crates with a deny-by-default posture. Sync and async (tokio) APIs.

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

Every agent action goes through a policy check first, and every decision — allow or deny — lands in a hash-chained audit log. Nothing is allowed unless a rule says so.

## Crates

| Crate | What it does |
|---|---|
| [`tai-core`](crates/tai-core) | shared event types |
| [`tai-policy`](crates/tai-policy) | policy engine: allow/deny rules with wildcards, deny overrides, default deny |
| [`tai-models`](crates/tai-models) | model router: sync + async (tokio), one interface for local/API models, fallback, timeouts |
| [`tai-sandbox`](crates/tai-sandbox) | tool sandbox: whitelist, timeouts, output and concurrency limits |
| [`tai-agents`](crates/tai-agents) | agent gate: sync and async agents, actions pass policy, results are audited |
| [`tai-audit`](crates/tai-audit) | JSONL audit log with SHA-256 hash chain (tamper-evident) |

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

Async on tokio — sync models run on the blocking pool via `register_sync`:

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

## Tool sandbox

Tools are whitelisted and capped by timeout, output size and concurrency; oversized output is truncated on char boundaries. Custom tools implement the async `Tool` trait.

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

## Agents

An agent binds a router, a policy, an audit log and (for async) a sandbox. `call_tool` checks `tool.call` on `{tool}:{input}` first, then executes inside the sandbox — denied actions never reach a tool.

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

agent.ask("hello").await.unwrap(); // allowed, audited
agent.call_tool("echo", "ping").await.unwrap(); // gated + sandboxed, audited
agent.call_tool("fs.write", "/etc").await.unwrap_err(); // default deny
```

A sync `Agent` with the same gate is also available for non-tokio code.

## Audit

Each JSONL line carries `prev` and `hash` — SHA-256 over the previous hash and the event, anchored to a genesis hash. Reopening the file continues the chain, so verification works across restarts. Any edit to a past line breaks it:

```rust
use tai_audit::AuditLog;

let audit = AuditLog::file("audit.jsonl")?;
audit.log(&Event::now("policy.allow", "assistant-1", "tool.call echo:ping"));

tai_audit::verify("audit.jsonl")?; // Ok(()) — chain intact
```

A line in the log:

```json
{"ts":1728000000,"kind":"policy.allow","actor":"assistant-1","detail":"tool.call echo:ping","prev":"000...0","hash":"9f2c..."}
```

## Roadmap

- [x] tool sandbox: whitelisted tools with execution limits
- [x] async API on tokio
- [x] hash-chained audit log (tamper evidence)
- [ ] streaming completions
- [ ] policy hot-reload
- [ ] external anchoring for the audit chain

## License

Apache-2.0 — see [LICENSE](LICENSE).
