# Trusted AI Infrastructure

[![CI](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml/badge.svg)](https://github.com/mel0k1/trusted-ai-infrastructure/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Trust layer for AI systems. Model routing with streaming, agent gates, permissions, tool sandbox and tamper-evident audit — small composable Rust crates with a deny-by-default posture. Sync and async (tokio) APIs.

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
| [`tai-policy`](crates/tai-policy) | policy engine: allow/deny rules with wildcards, deny overrides, default deny, hot-reload from file |
| [`tai-models`](crates/tai-models) | model router: sync + async (tokio), SSE streaming, fallback, timeouts |
| [`tai-sandbox`](crates/tai-sandbox) | tool sandbox: whitelist, timeouts, output and concurrency limits |
| [`tai-agents`](crates/tai-agents) | agent gate: sync and async agents, actions pass policy, results are audited |
| [`tai-audit`](crates/tai-audit) | JSONL audit log with SHA-256 hash chain and external anchoring (file / HTTP) |

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

### Hot-reload

`HotPolicy` watches a JSON file and swaps the live policy atomically. A malformed file never replaces the working policy — the error is reported and the old rules keep running.

```rust
use std::sync::Arc;
use std::time::Duration;
use tai_policy::HotPolicy;

let hot = HotPolicy::new("policy.json")?;
let watcher = hot.spawn_watcher(Duration::from_secs(5));

// always a fresh snapshot, lock-free checks on the Arc
let decision = hot.check("agent-1", "tool.call", "web.get:x");

hot.stop();
watcher.join().unwrap();
```

## Model router

Any OpenAI-compatible endpoint works: OpenAI, Ollama (`/v1`), vLLM, llama.cpp. The router tries models in order and falls back on failure; an optional timeout guards each attempt.

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

    // register_sync runs sync models on the blocking pool
    let router = AsyncRouter::new()
        .with_timeout(Duration::from_secs(60))
        .register(api)
        .register_sync(fallback);

    let answer = router.complete(&CompletionRequest::new("ping")).await.unwrap();
}
```

### Streaming

`stream` parses OpenAI SSE and pushes deltas into a `DeltaSink` (any `FnMut(&str) + Send`). Fallback only happens while no deltas have been emitted — once the stream started, a mid-stream error is fatal instead of duplicating output on the next model.

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

Agents stream through the same gate:

```rust
let text = agent.ask_stream("hello", &mut |d: &str| print!("{d}")).await.unwrap();
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

### External anchoring

A local chain can still be rewritten in full. Checkpoints fix that: every N events the chain head is published to an external `Anchor` (append-only file, HTTP endpoint, SIEM — implement the trait for anything else). The anchor itself is hash-chained, and checkpoints are verified against the log by height:

```rust
use tai_audit::{AuditLog, FileAnchor};

let anchor = FileAnchor::create("audit.anchor.jsonl");
let audit = AuditLog::file_anchored("audit.jsonl", Box::new(anchor), 100)?;
// every 100 events -> Checkpoint { height, head } goes to the anchor file

tai_audit::verify_with_anchor("audit.jsonl", "audit.anchor.jsonl")?; // Ok(())
```

A checkpoint line:

```json
{"height":200,"head":"fc14...","ts":1791123410,"prev":"c2ef...","hash":"63a9..."}
```

## Roadmap

- [x] tool sandbox: whitelisted tools with execution limits
- [x] async API on tokio
- [x] hash-chained audit log (tamper evidence)
- [x] streaming completions (SSE)
- [x] policy hot-reload
- [x] external anchoring (file / HTTP)
- [ ] RFC-3161 timestamping for checkpoints
- [ ] policy hot-reload from remote sources

## License

Apache-2.0 — see [LICENSE](LICENSE).
