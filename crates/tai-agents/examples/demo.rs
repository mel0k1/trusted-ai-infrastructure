//! Пример: агент поверх echo-модели с policy и аудитом.
//!
//! cargo run --example demo -p tai-agents

use std::sync::Arc;

use tai_agents::Agent;
use tai_audit::AuditLog;
use tai_models::{Echo, Router};
use tai_policy::Policy;

fn main() {
    // invoke моделей и web.get разрешены, fs.write запрещён явно, остальное — default deny
    let policy = Arc::new(
        Policy::new()
            .allow("demo-agent", "model.invoke", "model:*")
            .allow("demo-agent", "tool.call", "web.get:*")
            .deny("demo-agent", "tool.call", "fs.write:*"),
    );

    let router = Arc::new(Router::new().register(Arc::new(Echo::new("local-echo"))));
    let agent = Agent::new("demo-agent", router, policy, Arc::new(AuditLog::stderr()));

    match agent.ask("hello there") {
        Ok(text) => println!("answer: {text}"),
        Err(e) => println!("rejected: {e}"),
    }

    println!(
        "web.get allowed: {}",
        agent
            .ensure_allowed("tool.call", "web.get:example.com")
            .is_ok()
    );
    println!(
        "fs.write allowed: {}",
        agent
            .ensure_allowed("tool.call", "fs.write:/etc/passwd")
            .is_ok()
    );
}
