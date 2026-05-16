//! Per-node routed message propagation and sensor emit loops.

use std::sync::{Arc, Mutex};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use embassy_time::{Duration, Timer};
use rand::Rng as _;

use routing_core::config::DEFAULT_TTL;
use routing_core::facade::{
    broadcast_destination, decide_routed_message, RoutedDecision, RoutedEnvelope,
};
use routing_core::node::roles::Capabilities;
use routing_core::protocol::packet::PACKET_TYPE_DATA;
use routing_core::routing::table::RoutingTable;
use routing_core::store_forward::retain_for_low_power_destination;

use crate::medium::{SimDataMessage, SimMedium};
use crate::network::SimNodeInfo;
use crate::sim_state::{
    MessageKind, NodeType, SimConfig, TraceEventKind, TraceStatus, TuiState, MAX_NODES,
};
use crate::store_forward::StoreForwardState;

/// Receives routed application messages, applies shared routing-core forwarding
/// decisions, and records hop-by-hop trace events.
pub async fn run_message_loop(
    node_idx: usize,
    medium: &'static SimMedium,
    routing_table: &'static AsyncMutex<CriticalSectionRawMutex, RoutingTable>,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
    sim_config: Arc<Mutex<SimConfig>>,
    tui_state: Arc<Mutex<TuiState>>,
    store_forward_state: Arc<Mutex<StoreForwardState>>,
) -> ! {
    loop {
        let msg = medium.msg_inbox[node_idx].receive().await;

        {
            let mut state = tui_state.lock().unwrap();
            state.push_trace_event(
                msg.trace_id,
                node_idx,
                msg.ttl,
                msg.hop_count,
                TraceEventKind::Received {
                    from_node: msg.sender_idx,
                },
                format!(
                    "node {} received packet from {} (ttl={}, hop={})",
                    node_idx, msg.sender_idx, msg.ttl, msg.hop_count
                ),
            );
        }

        let destination = if msg.is_broadcast {
            broadcast_destination()
        } else {
            all_nodes[msg.to_idx].short_addr
        };
        let destination_is_low_power = !msg.is_broadcast && {
            let cfg = sim_config.lock().unwrap();
            Capabilities::is_low_power_endpoint_bits(cfg.capabilities[msg.to_idx])
        };
        let holder_caps = {
            let cfg = sim_config.lock().unwrap();
            cfg.capabilities[node_idx]
        };
        let routed = RoutedEnvelope {
            destination,
            is_broadcast: msg.is_broadcast,
            message_id: msg.message_id,
            ttl: msg.ttl,
            hop_count: msg.hop_count,
        };
        let decision = {
            let mut table = routing_table.lock().await;
            decide_routed_message(
                &mut table,
                holder_caps,
                destination_is_low_power,
                all_nodes[node_idx].short_addr,
                routed,
            )
        };

        if msg.is_broadcast {
            let mut state = tui_state.lock().unwrap();
            state.msgs_received[node_idx] = state.msgs_received[node_idx].saturating_add(1);
            state.push_trace_event(
                msg.trace_id,
                node_idx,
                msg.ttl,
                msg.hop_count,
                TraceEventKind::ObservedBroadcast,
                "broadcast observed at node",
            );
        }

        match decision {
            RoutedDecision::TtlExpired => {
                let mut state = tui_state.lock().unwrap();
                state.push_trace_event(
                    msg.trace_id,
                    node_idx,
                    msg.ttl,
                    msg.hop_count,
                    TraceEventKind::TtlExpired,
                    "ttl exhausted before processing",
                );
                state.set_trace_terminal_status(msg.trace_id, TraceStatus::TtlExpired);
                continue;
            }
            RoutedDecision::Duplicate => {
                let mut state = tui_state.lock().unwrap();
                state.push_trace_event(
                    msg.trace_id,
                    node_idx,
                    msg.ttl,
                    msg.hop_count,
                    TraceEventKind::Deduped,
                    "dedup rejected packet",
                );
                state.set_trace_terminal_status(msg.trace_id, TraceStatus::Deduped);
                continue;
            }
            RoutedDecision::DeliveredLocal => {
                let mut state = tui_state.lock().unwrap();
                state.push_trace_event(
                    msg.trace_id,
                    node_idx,
                    msg.ttl,
                    msg.hop_count,
                    TraceEventKind::Delivered,
                    "destination consumed packet",
                );
                state.mark_trace_delivered(msg.trace_id);
                state.msgs_received[node_idx] = state.msgs_received[node_idx].saturating_add(1);
                continue;
            }
            RoutedDecision::NoRoute {
                should_retain_for_lpn,
                ..
            } => {
                if should_retain_for_lpn {
                    let body = tui_state
                        .lock()
                        .unwrap()
                        .traces
                        .iter()
                        .find(|trace| trace.id == msg.trace_id)
                        .map(|trace| trace.body.clone())
                        .unwrap_or_default();
                    let now_secs = tui_state.lock().unwrap().elapsed_secs;
                    let retained = retain_for_low_power_destination(
                        &mut *store_forward_state.lock().unwrap(),
                        msg.trace_id,
                        msg.message_id,
                        all_nodes[msg.from_idx].short_addr,
                        all_nodes[msg.to_idx].short_addr,
                        all_nodes[node_idx].short_addr,
                        all_nodes[node_idx].short_addr,
                        body.as_bytes(),
                        now_secs,
                    );

                    if retained {
                        let mut state = tui_state.lock().unwrap();
                        state.push_trace_event(
                            msg.trace_id,
                            node_idx,
                            msg.ttl,
                            msg.hop_count,
                            TraceEventKind::Deferred,
                            format!(
                                "router {} retained packet for low-power destination {}",
                                node_idx, msg.to_idx
                            ),
                        );
                        continue;
                    }
                }

                let mut state = tui_state.lock().unwrap();
                state.push_trace_event(
                    msg.trace_id,
                    node_idx,
                    msg.ttl,
                    msg.hop_count,
                    TraceEventKind::NoRoute,
                    "no forwarding candidate from routing table",
                );
                state.set_trace_terminal_status(
                    msg.trace_id,
                    if msg.is_broadcast {
                        TraceStatus::Delivered
                    } else {
                        TraceStatus::NoRoute
                    },
                );
                continue;
            }
            RoutedDecision::Forward {
                candidates,
                should_retain_for_lpn,
            } => {
                let mut forwarded_any = false;
                let mut had_drop = false;

                for (_peer_addr, transport) in candidates.iter().copied() {
                    let next_idx = transport.addr[0] as usize;
                    if next_idx >= MAX_NODES || next_idx == msg.sender_idx || next_idx == node_idx {
                        continue;
                    }

                    let (active, link_enabled, drop_prob) = {
                        let cfg = sim_config.lock().unwrap();
                        (
                            next_idx < cfg.n_active,
                            cfg.link_enabled[node_idx][next_idx],
                            cfg.drop_prob[node_idx][next_idx],
                        )
                    };

                    if !active || !link_enabled {
                        tui_state.lock().unwrap().push_trace_event(
                            msg.trace_id,
                            node_idx,
                            msg.ttl,
                            msg.hop_count,
                            TraceEventKind::Blocked { to_node: next_idx },
                            format!("candidate {} blocked by inactive/disabled link", next_idx),
                        );
                        continue;
                    }

                    if drop_prob > 0 && rand::thread_rng().gen_range(0u8..100) < drop_prob {
                        had_drop = true;
                        let mut state = tui_state.lock().unwrap();
                        state.push_trace_event(
                            msg.trace_id,
                            node_idx,
                            msg.ttl,
                            msg.hop_count,
                            TraceEventKind::Dropped {
                                to_node: Some(next_idx),
                            },
                            format!(
                                "candidate {} dropped by simulated loss ({}%)",
                                next_idx, drop_prob
                            ),
                        );
                        continue;
                    }

                    let forwarded = SimDataMessage {
                        trace_id: msg.trace_id,
                        from_idx: msg.from_idx,
                        to_idx: msg.to_idx,
                        is_broadcast: msg.is_broadcast,
                        sender_idx: node_idx,
                        message_id: msg.message_id,
                        ttl: msg.ttl.saturating_sub(1),
                        hop_count: msg.hop_count.saturating_add(1),
                    };

                    medium.msg_inbox[next_idx].send(forwarded).await;
                    forwarded_any = true;

                    tui_state.lock().unwrap().push_trace_event(
                        msg.trace_id,
                        node_idx,
                        msg.ttl.saturating_sub(1),
                        msg.hop_count.saturating_add(1),
                        TraceEventKind::Forwarded { to_node: next_idx },
                        format!("forwarded to node {} via {:02x?}", next_idx, transport.addr),
                    );
                }
                if !forwarded_any {
                    if should_retain_for_lpn {
                        let body = tui_state
                            .lock()
                            .unwrap()
                            .traces
                            .iter()
                            .find(|trace| trace.id == msg.trace_id)
                            .map(|trace| trace.body.clone())
                            .unwrap_or_default();
                        let now_secs = tui_state.lock().unwrap().elapsed_secs;
                        let retained = retain_for_low_power_destination(
                            &mut *store_forward_state.lock().unwrap(),
                            msg.trace_id,
                            msg.message_id,
                            all_nodes[msg.from_idx].short_addr,
                            all_nodes[msg.to_idx].short_addr,
                            all_nodes[node_idx].short_addr,
                            all_nodes[node_idx].short_addr,
                            body.as_bytes(),
                            now_secs,
                        );
                        if retained {
                            let mut state = tui_state.lock().unwrap();
                            state.push_trace_event(
                                msg.trace_id,
                                node_idx,
                                msg.ttl,
                                msg.hop_count,
                                TraceEventKind::Deferred,
                                format!(
                                    "router {} retained packet for low-power destination {} after transient forward failure",
                                    node_idx, msg.to_idx
                                ),
                            );
                            continue;
                        }
                    }

                    let mut state = tui_state.lock().unwrap();
                    state.push_trace_event(
                        msg.trace_id,
                        node_idx,
                        msg.ttl,
                        msg.hop_count,
                        if msg.ttl <= 1 {
                            TraceEventKind::TtlExpired
                        } else {
                            TraceEventKind::NoRoute
                        },
                        "no candidate accepted packet",
                    );
                    if msg.ttl <= 1 {
                        state.set_trace_terminal_status(msg.trace_id, TraceStatus::TtlExpired);
                    } else if had_drop {
                        state.set_trace_terminal_status(msg.trace_id, TraceStatus::Dropped);
                    } else if msg.is_broadcast {
                        state.set_trace_terminal_status(msg.trace_id, TraceStatus::Delivered);
                    } else {
                        state.set_trace_terminal_status(msg.trace_id, TraceStatus::NoRoute);
                    }
                }
            }
        }
    }
}

/// Periodically emits routed sensor readings for Sensor and FullNode nodes.
pub async fn run_sensor_loop(
    node_idx: usize,
    medium: &'static SimMedium,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
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

        let target_idx = loop {
            let idx = rand::thread_rng().gen_range(0..n_active);
            if idx != node_idx {
                break idx;
            }
        };

        let temp: f32 = 20.0 + rand::thread_rng().gen_range(0.0f32..10.0);
        let body_str = format!("{:.1}°C", temp);

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

            let message_id = sensor_message_id(node_idx, target_idx, &body_str);
            let trace_id = {
                let mut state = tui_state.lock().unwrap();
                state.create_trace(
                    node_idx,
                    target_idx,
                    MessageKind::Temperature,
                    body_str.clone(),
                    source_caps,
                    target_caps,
                    PACKET_TYPE_DATA,
                    0,
                    all_nodes[target_idx].short_addr,
                    false,
                    link_enabled_at_send,
                    drop_prob_at_send,
                    message_id,
                    DEFAULT_TTL,
                )
            };

            let msg = SimDataMessage {
                trace_id,
                from_idx: node_idx,
                to_idx: target_idx,
                is_broadcast: false,
                sender_idx: node_idx,
                message_id,
                ttl: DEFAULT_TTL,
                hop_count: 0,
            };
            medium.msg_inbox[node_idx].send(msg).await;
            let mut state = tui_state.lock().unwrap();
            state.msgs_sent[node_idx] = state.msgs_sent[node_idx].saturating_add(1);
            state.push_trace_event(
                trace_id,
                node_idx,
                DEFAULT_TTL,
                0,
                TraceEventKind::Queued,
                format!(
                    "sensor message queued at source for destination {}",
                    target_idx
                ),
            );
        }
    }
}

fn sensor_message_id(from: usize, to: usize, body: &str) -> [u8; 8] {
    let mut id = [0u8; 8];
    id[0] = from as u8;
    id[1] = to as u8;
    for (i, byte) in body.as_bytes().iter().take(6).enumerate() {
        id[i + 2] = *byte;
    }
    id
}
