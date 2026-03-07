//! Per-node message receive and sensor emit loops.

use std::sync::{Arc, Mutex};

use embassy_time::{Duration, Timer};
use rand::Rng as _;

use crate::medium::SimMedium;
use crate::sim_state::{MessageEntry, MessageKind, NodeType, SimConfig, TuiState, MAX_NODES};

/// Receives application messages from `msg_inbox[node_idx]` and logs them.
pub async fn run_message_loop(
    node_idx: usize,
    medium: &'static SimMedium,
    tui_state: Arc<Mutex<TuiState>>,
) -> ! {
    loop {
        let msg = medium.msg_inbox[node_idx].receive().await;

        let elapsed = tui_state.lock().unwrap().elapsed_secs;
        let entry = MessageEntry {
            time_secs: elapsed,
            from_idx: msg.from_idx,
            to_idx: msg.to_idx,
            kind: msg.kind,
            body: msg.body.as_str().to_string(),
        };

        if let Ok(mut state) = tui_state.try_lock() {
            state.push_message(entry);
        }
    }
}

/// Periodically emits sensor readings for Sensor and FullNode nodes.
///
/// Sends to a random active peer via `msg_inbox`; the recipient's
/// `run_message_loop` logs the message.
pub async fn run_sensor_loop(
    node_idx: usize,
    medium: &'static SimMedium,
    sim_config: Arc<Mutex<SimConfig>>,
    _tui_state: Arc<Mutex<TuiState>>,
) -> ! {
    loop {
        let (interval, sensor_auto, n_active, node_type) = {
            let cfg = sim_config.lock().unwrap();
            (cfg.sensor_interval_secs, cfg.sensor_auto, cfg.n_active, cfg.node_types[node_idx])
        };

        Timer::after(Duration::from_secs(interval)).await;

        if !sensor_auto || node_idx >= n_active {
            continue;
        }
        if !matches!(node_type, NodeType::Sensor | NodeType::FullNode) {
            continue;
        }
        if n_active < 2 {
            continue;
        }

        // Pick a random active peer.
        let target_idx = loop {
            let idx = rand::thread_rng().gen_range(0..n_active);
            if idx != node_idx {
                break idx;
            }
        };

        let temp: f32 = 20.0 + rand::thread_rng().gen_range(0.0f32..10.0);
        let body_str = format!("{:.1}°C", temp);
        let mut body = heapless::String::<64>::new();
        let _ = body.push_str(&body_str);

        let msg = crate::medium::SimDataMessage {
            from_idx: node_idx,
            to_idx: target_idx,
            kind: MessageKind::Temperature,
            body,
        };

        // Deliver to target's inbox (message_loop on that node logs it).
        if target_idx < MAX_NODES {
            medium.msg_inbox[target_idx].send(msg).await;
        }
    }
}
