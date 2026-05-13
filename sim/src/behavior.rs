//! Simulator-specific behavior loops.
//!
//! These wrap the shared routing-core behavior helpers but fetch node
//! capabilities from `SimConfig` at runtime, so scenario switches can change
//! advertised roles without restarting the simulator.

use std::sync::{Arc, Mutex};

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use embassy_time::{Duration, Instant, Timer};
use heapless::Vec as HeaplessVec;

use routing_core::behavior::{
    apply_discovery_events, build_h2h_payload, collect_h2h_peer_snapshots, is_backup_router_for_lpn,
};
use routing_core::config::H2H_CYCLE_SECS;
use routing_core::crypto::identity::{short_addr_of, NodeIdentity};
use routing_core::network::{H2hInitiator, H2hResponder};
use routing_core::node::roles::Capabilities;
use routing_core::protocol::h2h::{self, H2hFrame, H2H_DELIVERY_BODY_MAX};
use routing_core::routing::table::RoutingTable;

use crate::sim_state::{SimConfig, MAX_NODES};
use crate::sim_state::{TraceEventKind, TuiState};
use crate::store_forward::StoreForwardState;

const DISCOVERY_DURATION_MS: u64 = 7_000;

fn current_capabilities(sim_config: &Arc<Mutex<SimConfig>>, node_idx: usize) -> u16 {
    let cfg = sim_config.lock().unwrap();
    if node_idx < MAX_NODES {
        cfg.capabilities[node_idx]
    } else {
        0
    }
}

pub async fn run_responder_loop_dynamic<M, R>(
    node_idx: usize,
    responder: &mut R,
    identity: &NodeIdentity,
    routing_table: &AsyncMutex<M, RoutingTable>,
    uptime: &AsyncMutex<M, u32>,
    sim_config: Arc<Mutex<SimConfig>>,
    store_forward_state: Arc<Mutex<StoreForwardState>>,
    tui_state: Arc<Mutex<TuiState>>,
) -> !
where
    M: RawMutex,
    R: H2hResponder,
{
    let addr_bytes = identity.short_addr();
    let jitter_ms = u16::from_le_bytes([addr_bytes[0], addr_bytes[1]]) % 2048;
    Timer::after(Duration::from_millis(jitter_ms as u64)).await;

    loop {
        match responder.receive_h2h().await {
            Ok(inbound) => {
                let partner_short = match inbound.peer_payload.full_pubkey {
                    Some(pk) => short_addr_of(&pk),
                    None => {
                        let table = routing_table.lock().await;
                        table
                            .peers
                            .iter()
                            .find(|p| p.transport_addr == inbound.peer_transport_addr)
                            .map(|p| p.short_addr)
                            .unwrap_or([0u8; 8])
                    }
                };

                let capabilities = current_capabilities(&sim_config, node_idx);
                let response = build_h2h_payload(
                    identity,
                    capabilities,
                    uptime,
                    routing_table,
                    &partner_short,
                )
                .await;

                {
                    let mut table = routing_table.lock().await;
                    table.update_peer_from_h2h(
                        &inbound.peer_payload,
                        partner_short,
                        inbound.peer_transport_addr,
                        Instant::now().as_ticks(),
                    );
                }

                if let Err(e) = responder.send_h2h_response(&response).await {
                    log::warn!("[sim-periph] send_h2h_response error: {:?}", e);
                    let _ = responder.finish_h2h_session().await;
                    continue;
                }

                let partner_idx = inbound
                    .peer_transport_addr
                    .as_ble_mac()
                    .map(|mac| mac[0] as usize)
                    .unwrap_or(MAX_NODES);
                let partner_caps = if partner_idx < MAX_NODES {
                    current_capabilities(&sim_config, partner_idx)
                } else {
                    0
                };

                // Low-power endpoints explicitly wake a router to collect any
                // delayed deliveries buffered on their behalf.
                //
                // This branch handles the LPN-facing half of the extended H2H
                // session: sync first, then pending summary, then retained data
                // frames, then acknowledgements.
                if Capabilities::is_low_power_endpoint_bits(partner_caps) {
                    let pending = store_forward_state
                        .lock()
                        .unwrap()
                        .pending_for_delivery(node_idx, partner_idx);

                    let summary = H2hFrame::DeliverySummary {
                        pending_count: pending.len().min(u8::MAX as usize) as u8,
                        preferred_router: true,
                    };

                    if responder.send_h2h_frame(&summary).await.is_ok() {
                        let mut state = tui_state.lock().unwrap();
                        for entry in pending.iter() {
                            state.push_trace_event(
                                entry.trace_id,
                                node_idx,
                                0,
                                0,
                                TraceEventKind::PendingAnnounced {
                                    count: pending.len(),
                                },
                                format!(
                                    "router {} announced {} pending retained deliveries to LPN {}",
                                    node_idx,
                                    pending.len(),
                                    partner_idx
                                ),
                            );
                        }
                    }

                    let mut acked = HeaplessVec::<u64, 8>::new();
                    for entry in pending.iter() {
                        let mut body = heapless::Vec::new();
                        for byte in entry.body.as_bytes().iter().take(H2H_DELIVERY_BODY_MAX) {
                            let _ = body.push(*byte);
                        }
                        let frame = H2hFrame::DeliveryData {
                            trace_id: entry.trace_id,
                            message_id: entry.message_id,
                            source_idx: entry.from_idx as u8,
                            destination_idx: entry.to_idx as u8,
                            body,
                        };

                        if responder.send_h2h_frame(&frame).await.is_err() {
                            break;
                        }

                        match responder.receive_h2h_frame().await {
                            Ok(H2hFrame::DeliveryAck { trace_ids }) => {
                                for trace_id in trace_ids {
                                    let _ = acked.push(trace_id);
                                    tui_state.lock().unwrap().push_trace_event(
                                        trace_id,
                                        node_idx,
                                        0,
                                        0,
                                        TraceEventKind::DeliveryConfirmed {
                                            lpn_node: partner_idx,
                                        },
                                        format!(
                                            "router {} received delayed-delivery confirmation from LPN {}",
                                            node_idx, partner_idx
                                        ),
                                    );
                                }
                            }
                            Ok(H2hFrame::SessionDone) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }

                    if !acked.is_empty() {
                        store_forward_state
                            .lock()
                            .unwrap()
                            .ack_delivered(node_idx, acked.as_slice());
                    }

                    // Close the LPN wake session explicitly so the initiator
                    // loop can advance instead of waiting on another frame.
                    let _ = responder.send_h2h_frame(&H2hFrame::SessionDone).await;
                } else if Capabilities::is_store_router_bits(capabilities)
                    && Capabilities::is_store_router_bits(partner_caps)
                {
                    // Router-to-router redundancy path, responder phase.
                    // The responder sends its retention state first, then keeps
                    // the session open so the initiator can send its own phase.
                    let tombstones = {
                        let state = store_forward_state.lock().unwrap();
                        state.tombstones().to_vec()
                    };
                    if !tombstones.is_empty() {
                        let mut trace_ids = heapless::Vec::new();
                        for trace_id in tombstones
                            .iter()
                            .take(routing_core::protocol::h2h::H2H_ACK_IDS_MAX)
                        {
                            let _ = trace_ids.push(*trace_id);
                        }
                        let _ = responder
                            .send_h2h_frame(&H2hFrame::RetentionTombstone { trace_ids })
                            .await;
                    }

                    let replication_candidates = store_forward_state
                        .lock()
                        .unwrap()
                        .replication_candidates(node_idx);

                    let known_store_routers = {
                        let table = routing_table.lock().await;
                        let mut routers = Vec::new();
                        if Capabilities::is_store_router_bits(capabilities) {
                            routers.push(*identity.short_addr());
                        }
                        for peer in table.peers.iter() {
                            if Capabilities::is_store_router_bits(peer.capabilities)
                                && !routers.iter().any(|existing| *existing == peer.short_addr)
                            {
                                routers.push(peer.short_addr);
                            }
                        }
                        routers
                    };

                    for entry in replication_candidates {
                        let lpn_short = if entry.to_idx < MAX_NODES {
                            tui_state.lock().unwrap().node_short_addrs[entry.to_idx]
                        } else {
                            continue;
                        };

                        // Replicas are only seeded onto the deterministic
                        // backup subset for this LPN. The owner may be chosen
                        // by primary link quality, but backup placement must be
                        // shared and stable so any router can reason about the
                        // same fallback set.
                        if !is_backup_router_for_lpn(
                            &lpn_short,
                            &partner_short,
                            known_store_routers.as_slice(),
                        ) {
                            continue;
                        }

                        let mut body = heapless::Vec::new();
                        for byte in entry.body.as_bytes().iter().take(H2H_DELIVERY_BODY_MAX) {
                            let _ = body.push(*byte);
                        }

                        let frame = H2hFrame::RetentionReplica {
                            trace_id: entry.trace_id,
                            message_id: entry.message_id,
                            source_idx: entry.from_idx as u8,
                            destination_idx: entry.to_idx as u8,
                            owner_router_idx: entry.owner_router_idx as u8,
                            body,
                        };

                        if responder.send_h2h_frame(&frame).await.is_err() {
                            break;
                        }

                        match responder.receive_h2h_frame().await {
                            Ok(H2hFrame::RetentionAck { trace_ids }) => {
                                let _ = trace_ids;
                            }
                            Ok(H2hFrame::SessionDone) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }

                    let _ = responder.send_h2h_frame(&H2hFrame::SessionDone).await;

                    loop {
                        match responder.receive_h2h_frame().await {
                            Ok(H2hFrame::RetentionTombstone { trace_ids }) => {
                                store_forward_state
                                    .lock()
                                    .unwrap()
                                    .apply_tombstones(trace_ids.as_slice());
                            }
                            Ok(H2hFrame::RetentionReplica {
                                trace_id,
                                message_id,
                                source_idx,
                                destination_idx,
                                owner_router_idx,
                                body,
                            }) => {
                                let retained = store_forward_state.lock().unwrap().retain_replica(
                                    crate::store_forward::RetainedMessage {
                                        trace_id,
                                        message_id,
                                        from_idx: source_idx as usize,
                                        to_idx: destination_idx as usize,
                                        holder_idx: node_idx,
                                        owner_router_idx: owner_router_idx as usize,
                                        body: String::from_utf8_lossy(body.as_slice()).into_owned(),
                                        enqueued_at_secs: tui_state.lock().unwrap().elapsed_secs,
                                        announced: false,
                                    },
                                );

                                if retained {
                                    let mut trace_ids = heapless::Vec::new();
                                    let _ = trace_ids.push(trace_id);
                                    let _ = responder
                                        .send_h2h_frame(&H2hFrame::RetentionAck { trace_ids })
                                        .await;
                                }
                            }
                            Ok(H2hFrame::SessionDone) => break,
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }

                let _ = responder.finish_h2h_session().await;
            }
            Err(e) => {
                log::warn!("[sim-periph] receive_h2h error: {:?}", e);
            }
        }
    }
}

pub async fn run_initiator_loop_dynamic<M, I>(
    node_idx: usize,
    initiator: &mut I,
    identity: &NodeIdentity,
    routing_table: &AsyncMutex<M, RoutingTable>,
    uptime: &AsyncMutex<M, u32>,
    sim_config: Arc<Mutex<SimConfig>>,
    store_forward_state: Arc<Mutex<StoreForwardState>>,
    tui_state: Arc<Mutex<TuiState>>,
) -> !
where
    M: RawMutex,
    I: H2hInitiator,
{
    Timer::after(Duration::from_secs(3)).await;

    loop {
        let cycle_start = Instant::now();

        let events = initiator.scan(DISCOVERY_DURATION_MS).await;
        apply_discovery_events(routing_table, &events).await;

        let our_addr = *identity.short_addr();
        let capabilities = current_capabilities(&sim_config, node_idx);
        let peer_snapshots =
            collect_h2h_peer_snapshots(identity, capabilities, routing_table).await;

        for (peer_addr, peer_transport_addr) in peer_snapshots.iter() {
            let offset = if Capabilities::is_low_power_endpoint_bits(capabilities) {
                0
            } else {
                h2h::slot_offset(&our_addr, peer_addr)
            };
            let target_time = cycle_start + Duration::from_secs(offset);

            if Instant::now() < target_time {
                Timer::at(target_time).await;
            }

            let payload =
                build_h2h_payload(identity, capabilities, uptime, routing_table, peer_addr).await;

            match initiator.initiate_h2h(*peer_transport_addr, &payload).await {
                Ok(peer_payload) => {
                    let mut table = routing_table.lock().await;
                    table.update_peer_from_h2h(
                        &peer_payload,
                        *peer_addr,
                        *peer_transport_addr,
                        Instant::now().as_ticks(),
                    );

                    if Capabilities::is_low_power_endpoint_bits(capabilities) {
                        let peer_node_idx = peer_transport_addr
                            .as_ble_mac()
                            .map(|mac| mac[0] as usize)
                            .unwrap_or(MAX_NODES);
                        loop {
                            match initiator.receive_h2h_frame().await {
                                Ok(H2hFrame::DeliverySummary { pending_count, .. }) => {
                                    if pending_count == 0 {
                                        continue;
                                    }
                                }
                                Ok(H2hFrame::DeliveryData { trace_id, .. }) => {
                                    tui_state.lock().unwrap().push_trace_event(
                                        trace_id,
                                        node_idx,
                                        0,
                                        0,
                                        TraceEventKind::LpnWakeSync {
                                            router_node: peer_node_idx,
                                        },
                                        format!(
                                            "LPN {} woke router {} for delayed-delivery sync",
                                            node_idx, peer_node_idx
                                        ),
                                    );
                                    tui_state.lock().unwrap().push_trace_event(
                                        trace_id,
                                        node_idx,
                                        0,
                                        0,
                                        TraceEventKind::DeliveredFromStore {
                                            router_node: peer_node_idx,
                                        },
                                        format!(
                                            "LPN {} received retained delivery from router {}",
                                            node_idx, peer_node_idx
                                        ),
                                    );
                                    tui_state.lock().unwrap().mark_trace_delivered(trace_id);

                                    let mut trace_ids = heapless::Vec::new();
                                    let _ = trace_ids.push(trace_id);
                                    let ack = H2hFrame::DeliveryAck { trace_ids };
                                    let _ = initiator.send_h2h_frame(&ack).await;
                                }
                                Ok(H2hFrame::SessionDone) => break,
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                    } else if Capabilities::is_store_router_bits(capabilities) {
                        // Backup routers learn about retained deliveries through
                        // normal router↔router H2H sessions. If the preferred
                        // router drops out later, the LPN can fall through to a
                        // reachable backup router and still complete delivery.
                        loop {
                            match initiator.receive_h2h_frame().await {
                                Ok(H2hFrame::RetentionTombstone { trace_ids }) => {
                                    store_forward_state
                                        .lock()
                                        .unwrap()
                                        .apply_tombstones(trace_ids.as_slice());
                                }
                                Ok(H2hFrame::RetentionReplica {
                                    trace_id,
                                    message_id,
                                    source_idx,
                                    destination_idx,
                                    owner_router_idx,
                                    body,
                                }) => {
                                    let retained = store_forward_state
                                        .lock()
                                        .unwrap()
                                        .retain_replica(crate::store_forward::RetainedMessage {
                                            trace_id,
                                            message_id,
                                            from_idx: source_idx as usize,
                                            to_idx: destination_idx as usize,
                                            holder_idx: node_idx,
                                            owner_router_idx: owner_router_idx as usize,
                                            body: String::from_utf8_lossy(body.as_slice())
                                                .into_owned(),
                                            enqueued_at_secs: tui_state
                                                .lock()
                                                .unwrap()
                                                .elapsed_secs,
                                            announced: false,
                                        });

                                    if retained {
                                        let mut trace_ids = heapless::Vec::new();
                                        let _ = trace_ids.push(trace_id);
                                        let _ = initiator
                                            .send_h2h_frame(&H2hFrame::RetentionAck { trace_ids })
                                            .await;
                                    }
                                }
                                Ok(H2hFrame::SessionDone) => break,
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }

                        let known_store_routers = {
                            let table = routing_table.lock().await;
                            let mut routers = Vec::new();
                            if Capabilities::is_store_router_bits(capabilities) {
                                routers.push(*identity.short_addr());
                            }
                            for peer in table.peers.iter() {
                                if Capabilities::is_store_router_bits(peer.capabilities)
                                    && !routers.iter().any(|existing| *existing == peer.short_addr)
                                {
                                    routers.push(peer.short_addr);
                                }
                            }
                            routers
                        };

                        let tombstones = {
                            let state = store_forward_state.lock().unwrap();
                            state.tombstones().to_vec()
                        };
                        if !tombstones.is_empty() {
                            let mut trace_ids = heapless::Vec::new();
                            for trace_id in tombstones
                                .iter()
                                .take(routing_core::protocol::h2h::H2H_ACK_IDS_MAX)
                            {
                                let _ = trace_ids.push(*trace_id);
                            }
                            let _ = initiator
                                .send_h2h_frame(&H2hFrame::RetentionTombstone { trace_ids })
                                .await;
                        }

                        let replication_candidates = store_forward_state
                            .lock()
                            .unwrap()
                            .replication_candidates(node_idx);

                        for entry in replication_candidates {
                            let lpn_short = if entry.to_idx < MAX_NODES {
                                tui_state.lock().unwrap().node_short_addrs[entry.to_idx]
                            } else {
                                continue;
                            };
                            if !is_backup_router_for_lpn(
                                &lpn_short,
                                peer_addr,
                                known_store_routers.as_slice(),
                            ) {
                                continue;
                            }

                            let mut body = heapless::Vec::new();
                            for byte in entry.body.as_bytes().iter().take(H2H_DELIVERY_BODY_MAX) {
                                let _ = body.push(*byte);
                            }

                            let frame = H2hFrame::RetentionReplica {
                                trace_id: entry.trace_id,
                                message_id: entry.message_id,
                                source_idx: entry.from_idx as u8,
                                destination_idx: entry.to_idx as u8,
                                owner_router_idx: entry.owner_router_idx as u8,
                                body,
                            };

                            if initiator.send_h2h_frame(&frame).await.is_err() {
                                break;
                            }

                            match initiator.receive_h2h_frame().await {
                                Ok(H2hFrame::RetentionAck { .. }) => {}
                                Ok(H2hFrame::SessionDone) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }

                        let _ = initiator.send_h2h_frame(&H2hFrame::SessionDone).await;
                    }

                    let _ = initiator.finish_h2h_session().await;

                    // LPN wake cycles intentionally stop after the first
                    // successful router session. The candidate list is ranked
                    // so later peers are fallback targets, not additional sync
                    // partners for the same wake window.
                    if Capabilities::is_low_power_endpoint_bits(capabilities) {
                        break;
                    }
                }
                Err(e) => {
                    log::warn!(
                        "[sim-central] H2H failed to {:02x?}: {:?}",
                        &peer_addr[..4],
                        e
                    );
                }
            }
        }

        let elapsed = Instant::now() - cycle_start;
        let cycle = Duration::from_secs(H2H_CYCLE_SECS);
        if elapsed < cycle {
            Timer::after(cycle - elapsed).await;
        }
    }
}
