//! TUI → embassy command dispatcher.
//!
//! Polls the mpsc receiver for `SimCommand`s and dispatches them to the
//! medium or modifies `SimConfig` directly.

use std::sync::{Arc, Mutex};
use std::sync::mpsc::Receiver;

use embassy_time::{Duration, Timer};

use crate::medium::SimMedium;
use crate::sim_state::{SimCommand, SimConfig, TuiState, MAX_NODES};

pub async fn run_command_loop(
    cmd_rx: Arc<Mutex<Receiver<SimCommand>>>,
    medium: &'static SimMedium,
    sim_config: Arc<Mutex<SimConfig>>,
    tui_state: Arc<Mutex<TuiState>>,
) -> ! {
    loop {
        // Non-blocking poll — embassy tasks must not block.
        let cmd = cmd_rx.lock().unwrap().try_recv().ok();

        match cmd {
            Some(SimCommand::SendMessage { from, to, kind, body }) => {
                if to < MAX_NODES {
                    let mut heapless_body = heapless::String::<64>::new();
                    let truncated = &body[..body.len().min(64)];
                    let _ = heapless_body.push_str(truncated);

                    let msg = crate::medium::SimDataMessage {
                        from_idx: from,
                        to_idx: to,
                        kind,
                        body: heapless_body,
                    };
                    medium.msg_inbox[to].send(msg).await;
                }
            }

            Some(SimCommand::AddNode) => {
                let mut cfg = sim_config.lock().unwrap();
                if cfg.n_active < MAX_NODES {
                    cfg.n_active += 1;
                    log::info!("Node {} activated", cfg.n_active - 1);
                }
            }

            Some(SimCommand::RemoveNode(idx)) => {
                let mut cfg = sim_config.lock().unwrap();
                // Only deactivate the last active node to keep indices contiguous.
                if cfg.n_active > 1 && idx == cfg.n_active - 1 {
                    cfg.n_active -= 1;
                    log::info!("Node {} deactivated", idx);
                }
            }

            None => {
                // Nothing pending — yield to other tasks.
                Timer::after(Duration::from_millis(50)).await;
            }
        }

        // Suppress unused warning: tui_state is reserved for future per-command logging.
        let _ = &tui_state;
    }
}
