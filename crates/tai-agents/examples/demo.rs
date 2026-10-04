//! Пример: async-агент с sandbox и хэш-цепочкой аудита.
//!
//! cargo run --example demo -p tai-agents

use std::sync::Arc;
use std::time::Duration;

use tai_agents::AsyncAgent;
use tai_audit::AuditLog;
use tai_models::{AsyncRouter, Echo};
use tai_policy::Policy;
use tai_sandbox::{EchoTool, Limits, Sandbox};

#[tokio::main]
async fn main() {
    // invoke моделей и echo разрешены, fs.write запрещён явно, остальное — default deny
    let policy = Arc::new(
        Policy::new()
            .allow("demo-agent", "model.invoke", "model:*")
            .allow("demo-agent", "tool.call", "echo:*")
            .deny("demo-agent", "tool.call", "fs.write:*"),
    );

    let router = Arc::new(
        AsyncRouter::new()
            .with_timeout(Duration::from_secs(30))
            .register_sync(Arc::new(Echo::new("local-echo"))),
    );
    let sandbox = Arc::new(
        Sandbox::new(Limits {
            timeout: Duration::from_secs(5),
            max_output: 16 * 1024,
            max_concurrent: 4,
        })
        .register(Arc::new(EchoTool)),
    );
    let audit = Arc::new(AuditLog::file("audit.jsonl").expect("audit file"));

    let agent = AsyncAgent::new("demo-agent", router, policy, audit, sandbox);

    println!("answer: {}", agent.ask("hello there").await.unwrap());
    println!("echo: {}", agent.call_tool("echo", "ping").await.unwrap());
    if let Err(e) = agent.call_tool("fs.write", "/etc/passwd").await {
        println!("rejected: {e}");
    }

    match tai_audit::verify("audit.jsonl") {
        Ok(()) => println!("audit chain: ok"),
        Err(e) => println!("audit chain: {e}"),
    }
}
