use std::error::Error;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

use crate::ble;
use crate::diagnostics::state::SharedState;
use crate::node::storage::{load_or_create_local_node, LocalNodeRecord};

#[derive(Clone, Debug)]
pub enum CompanionCommand {
    EnrollSelected(String),
    ResetNetworkKey,
    SendPing { short_addr: [u8; 8] },
    SendMessage { short_addr: [u8; 8], body: String },
}

pub struct CompanionRuntime {
    pub shared: Arc<Mutex<SharedState>>,
    pub shutdown_tx: watch::Sender<bool>,
    pub cmd_tx: mpsc::Sender<CompanionCommand>,
    shutdown_rx: watch::Receiver<bool>,
    cmd_rx: mpsc::Receiver<CompanionCommand>,
    local_node: LocalNodeRecord,
}

impl CompanionRuntime {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let local_node = load_or_create_local_node()?;
        let shared = Arc::new(Mutex::new(SharedState::new(&local_node)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (cmd_tx, cmd_rx) = mpsc::channel();
        Ok(Self {
            shared,
            shutdown_tx,
            cmd_tx,
            shutdown_rx,
            cmd_rx,
            local_node,
        })
    }

    pub fn log_startup(&self) {
        log::info!(
            "Constellation Companion — short_addr={:02x?}",
            &self.local_node.short_addr[..4]
        );
    }

    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        ble::run(self.shared, self.local_node, self.shutdown_rx, self.cmd_rx).await?;
        Ok(())
    }
}
