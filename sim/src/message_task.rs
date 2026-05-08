//! Per-node message receive and sensor emit loops.

use std::sync::{Arc, Mutex};

use embassy_time::{Duration, Timer};
use rand::Rng as _;

use crate::medium::SimMedium;
use crate::sim_state::{MessageKind, NodeType, SimConfig, TuiState, MAX_NODES};

/// Receives application messages from `msg_inbox[node_idx]` and logs them.
pub async fn run_message_loop(
    node_idx: usize,
    medium: &'static SimMedium,
    tui_state: Arc<Mutex<TuiState>>,
) -> ! {
    loop {
        let msg = medium.msg_inbox[node_idx].receive().await;

        let mut state = tui_state.lock().unwrap();
        state.mark_trace_delivered(msg.trace_id);
        state.msgs_received[node_idx] = state.msgs_received[node_idx].saturating_add(1);
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
    tui_state: Arc<Mutex<TuiState>>,
) -> ! {
    loop {
        let (interval, sensor_auto, n_active, node_type, emit_sensor) = {
            let cfg = sim_config.lock().unwrap();
            (
                cfg.sensor_interval_secs,
                cfg.sensor_auto,
                cfg.n_active,
                cfg.node_types[node_idx],
                cfg.node_behaviors[node_idx].emit_sensor,
            )
        };

        Timer::after(Duration::from_secs(interval)).await;

        if !sensor_auto || node_idx >= n_active || !emit_sensor {
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
        // Deliver to target's inbox (message_loop on that node logs it).
        if target_idx < MAX_NODES {
            let (source_caps, target_caps, link_enabled_at_send, drop_prob_at_send) = {
                let cfg = sim_config.lock().unwrap();
                (
                    cfg.capabilities[node_idx],
                    cfg.capabilities[target_idx],
                    cfg.link_enabled[node_idx][target_idx],
                    cfg.drop_prob[node_idx][target_idx],
                )
            };

            let trace_id = {
                let mut state = tui_state.lock().unwrap();
                state.create_trace(
                    node_idx,
                    target_idx,
                    MessageKind::Temperature,
                    body_str.clone(),
                    source_caps,
                    target_caps,
                    link_enabled_at_send,
                    drop_prob_at_send,
                )
            };

            let msg = crate::medium::SimDataMessage { trace_id };
            medium.msg_inbox[target_idx].send(msg).await;
            let mut state = tui_state.lock().unwrap();
            state.msgs_sent[node_idx] = state.msgs_sent[node_idx].saturating_add(1);
        }
    }
}
