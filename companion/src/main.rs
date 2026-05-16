//! macOS companion binary entrypoint.
//!
//! Purpose: launch the companion runtime, BLE/event loop, and terminal UI for
//! diagnostics, onboarding, and operator-driven message flows.
//!
//! Design decisions:
//! - Keep process/thread assembly here while BLE, storage, diagnostics, and UI
//!   live in focused companion modules.
use std::error::Error;
use std::sync::Arc;
use std::thread;

mod ble;
mod diagnostics;
mod node;
mod onboarding;
mod runtime;
mod tui;

use crate::runtime::CompanionRuntime;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let runtime = CompanionRuntime::new()?;
    runtime.log_startup();

    let shared = Arc::clone(&runtime.shared);
    let shutdown = runtime.shutdown_tx.clone();
    let cmd_tx = runtime.cmd_tx.clone();

    let tui_thread = thread::Builder::new()
        .name("companion-tui".into())
        .spawn(move || tui::run(shared, shutdown, cmd_tx))?;

    let local = tokio::task::LocalSet::new();
    let result = local.run_until(runtime.run()).await;
    let tui_result = tui_thread.join().unwrap_or_else(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "companion TUI thread panicked",
        ))
    });

    if let Err(e) = tui_result {
        eprintln!("TUI error: {e}");
    }

    result
}
