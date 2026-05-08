//! TUI → embassy command dispatcher.
//!
//! Polls the mpsc receiver for `SimCommand`s and dispatches them to the
//! medium or modifies `SimConfig` directly.

use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use embassy_time::{Duration, Timer};

use routing_core::config::BROADCAST_ADDR;
use routing_core::config::DEFAULT_TTL;
use routing_core::protocol::packet::{FLAG_BROADCAST, PACKET_TYPE_DATA};
use routing_core::routing::table::RoutingTable;

use crate::medium::SimMedium;
use crate::network::SimNodeInfo;
use crate::scenario;
use crate::sim_state::{SimCommand, SimConfig, TraceEventKind, TuiState, MAX_NODES};

pub async fn run_command_loop(
    cmd_rx: Arc<Mutex<Receiver<SimCommand>>>,
    medium: &'static SimMedium,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
    sim_config: Arc<Mutex<SimConfig>>,
    tui_state: Arc<Mutex<TuiState>>,
    routing_tables: &'static [AsyncMutex<CriticalSectionRawMutex, RoutingTable>; MAX_NODES],
    uptimes: &'static [AsyncMutex<CriticalSectionRawMutex, u32>; MAX_NODES],
) -> ! {
    loop {
        // Non-blocking poll — embassy tasks must not block.
        let cmd = cmd_rx.lock().unwrap().try_recv().ok();

        match cmd {
            Some(SimCommand::SendMessage {
                from,
                to,
                kind,
                body,
            }) => {
                if to <= MAX_NODES {
                    let is_broadcast = to == MAX_NODES;
                    let (source_caps, target_caps, link_enabled_at_send, drop_prob_at_send) = {
                        let cfg = sim_config.lock().unwrap();
                        (
                            cfg.capabilities[from],
                            if is_broadcast {
                                0
                            } else {
                                cfg.capabilities[to]
                            },
                            if is_broadcast {
                                true
                            } else {
                                cfg.link_enabled[from][to]
                            },
                            if is_broadcast {
                                0
                            } else {
                                cfg.drop_prob[from][to]
                            },
                        )
                    };
                    let packet_flags = if is_broadcast { FLAG_BROADCAST } else { 0 };
                    let dst_addr = if is_broadcast {
                        BROADCAST_ADDR
                    } else {
                        all_nodes[to].short_addr
                    };

                    let trace_id = {
                        let mut state = tui_state.lock().unwrap();
                        let message_id = trace_id_to_message_id(state.next_trace_id);
                        state.create_trace(
                            from,
                            to,
                            kind,
                            body.clone(),
                            source_caps,
                            target_caps,
                            PACKET_TYPE_DATA,
                            packet_flags,
                            dst_addr,
                            is_broadcast,
                            link_enabled_at_send,
                            drop_prob_at_send,
                            message_id,
                            DEFAULT_TTL,
                        )
                    };

                    let message_id = trace_id_to_message_id(trace_id);

                    let msg = crate::medium::SimDataMessage {
                        trace_id,
                        from_idx: from,
                        to_idx: to,
                        is_broadcast,
                        sender_idx: from,
                        message_id,
                        ttl: DEFAULT_TTL,
                        hop_count: 0,
                    };
                    medium.msg_inbox[from].send(msg).await;
                    tui_state.lock().unwrap().push_trace_event(
                        trace_id,
                        from,
                        DEFAULT_TTL,
                        0,
                        TraceEventKind::Queued,
                        if is_broadcast {
                            "manual broadcast queued at source".to_string()
                        } else {
                            format!("manual message queued at source for destination {}", to)
                        },
                    );
                    let mut state = tui_state.lock().unwrap();
                    state.msgs_sent[from] = state.msgs_sent[from].saturating_add(1);
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

            Some(SimCommand::ApplyScenario(id)) => {
                let next_config = scenario::build_config(id);
                {
                    let mut cfg = sim_config.lock().unwrap();
                    *cfg = next_config;
                }

                for table in routing_tables.iter() {
                    let self_addr = {
                        let table = table.lock().await;
                        table.self_addr
                    };
                    *table.lock().await = RoutingTable::new(self_addr);
                }

                for uptime in uptimes.iter() {
                    *uptime.lock().await = 0;
                }

                tui_state.lock().unwrap().reset_runtime();

                let preset = scenario::preset(id);
                log::info!("Scenario applied: {}", preset.name);
            }

            None => {
                // Nothing pending — yield to other tasks.
                Timer::after(Duration::from_millis(50)).await;
            }
        }
    }
}

fn trace_id_to_message_id(trace_id: u64) -> [u8; 8] {
    trace_id.to_le_bytes()
}
