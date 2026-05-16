//! Companion BLE integration.
//!
//! Purpose: group macOS/CoreBluetooth runtime, constants, and networking glue
//! used by the companion process.
//!
//! Design decisions:
//! - Keep platform BLE integration here while shared protocol behavior stays in
//!   `routing-core`.
pub mod constants;
pub mod network;
pub mod runtime;

use std::error::Error;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use crate::diagnostics::state::SharedState;
use crate::node::storage::LocalNodeRecord;
use crate::runtime::CompanionCommand;

pub async fn run(
    shared: Arc<Mutex<SharedState>>,
    local_node: LocalNodeRecord,
    shutdown_rx: watch::Receiver<bool>,
    cmd_rx: mpsc::Receiver<CompanionCommand>,
) -> Result<(), Box<dyn Error>> {
    runtime::run(shared, local_node, shutdown_rx, cmd_rx).await
}
