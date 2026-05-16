//! Headless simulator harness helpers for deterministic tests and assertions.

use std::time::{Duration, Instant};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use embassy_time::with_timeout;

use routing_core::behavior::{
    build_h2h_payload, run_initiator_h2h_once as run_shared_initiator_h2h_once,
    run_initiator_store_forward_followups,
};
use routing_core::crypto::identity::ShortAddr;
use routing_core::network::H2hInitiator;
use routing_core::protocol::h2h::{H2hFrame, H2hPayload, PeerInfo};
use routing_core::routing::table::RoutingTable;
use routing_core::store_forward::{
    retained_body_from_bytes, RetainedMessage, StoreForwardBackend, StoreForwardObserver,
};
use routing_core::transport::TransportAddr;

use crate::config_ops;
use crate::network::SimInitiator;
use crate::runtime::SimRuntime;
use crate::scenario::ScenarioId;
use crate::sim_state::{
    MessageKind, MessageTrace, SimCommand, SimConfig, TraceEventKind, TraceStatus, TuiState,
    MAX_NODES,
};
use crate::store_forward::SharedStoreForwardBackend;
use routing_core::config::{BROADCAST_ADDR, DEFAULT_TTL};
use routing_core::protocol::packet::PACKET_TYPE_DATA;

pub struct SimHarness {
    runtime: SimRuntime,
}

struct HarnessObserver<'a> {
    tui_state: &'a std::sync::Mutex<TuiState>,
}

impl HarnessObserver<'_> {
    fn node_index_for(&self, addr: ShortAddr) -> usize {
        self.tui_state
            .lock()
            .unwrap()
            .node_short_addrs
            .iter()
            .position(|candidate| *candidate == addr)
            .unwrap_or(0)
    }
}

impl StoreForwardObserver for HarnessObserver<'_> {
    fn on_delivered_from_store(
        &mut self,
        trace_id: u64,
        router_addr: ShortAddr,
        lpn_addr: ShortAddr,
    ) {
        let router_idx = self.node_index_for(router_addr);
        let lpn_idx = self.node_index_for(lpn_addr);
        let mut tui = self.tui_state.lock().unwrap();
        tui.push_trace_event(
            trace_id,
            lpn_idx,
            0,
            0,
            TraceEventKind::LpnWakeSync {
                router_node: router_idx,
            },
            format!(
                "LPN {} woke router {} for delayed-delivery sync",
                lpn_idx, router_idx
            ),
        );
        tui.push_trace_event(
            trace_id,
            lpn_idx,
            0,
            0,
            TraceEventKind::DeliveredFromStore {
                router_node: router_idx,
            },
            format!(
                "LPN {} received retained delivery from router {}",
                lpn_idx, router_idx
            ),
        );
        tui.mark_trace_delivered(trace_id);
    }
}

impl SimHarness {
    pub fn from_scenario(id: ScenarioId) -> Self {
        Self {
            runtime: SimRuntime::from_scenario(id),
        }
    }

    pub fn new(config: SimConfig) -> Self {
        Self {
            runtime: SimRuntime::start(config),
        }
    }

    pub fn state(&self) -> TuiState {
        self.runtime.tui_state.lock().unwrap().clone()
    }

    pub fn config(&self) -> SimConfig {
        self.runtime.sim_config.lock().unwrap().clone()
    }

    pub fn update_config(&self, f: impl FnOnce(&mut SimConfig)) {
        let mut cfg = self.runtime.sim_config.lock().unwrap();
        f(&mut cfg);
    }

    pub fn schedule_action(
        &self,
        after: Duration,
        action: impl FnOnce(&mut SimConfig) + Send + 'static,
    ) {
        let sim_config = self.runtime.sim_config.clone();
        std::thread::spawn(move || {
            std::thread::sleep(after);
            let mut cfg = sim_config.lock().unwrap();
            action(&mut cfg);
        });
    }

    pub fn schedule_link_enabled(&self, after: Duration, from: usize, to: usize, enabled: bool) {
        self.schedule_action(after, move |cfg| {
            config_ops::set_link_enabled(cfg, from, to, enabled);
        });
    }

    pub fn schedule_bidirectional_link(&self, after: Duration, a: usize, b: usize, enabled: bool) {
        self.schedule_action(after, move |cfg| {
            config_ops::set_bidirectional_link(cfg, a, b, enabled);
        });
    }

    pub fn schedule_capabilities(&self, after: Duration, node: usize, capabilities: u16) {
        self.schedule_action(after, move |cfg| {
            config_ops::set_capabilities(cfg, node, capabilities);
        });
    }

    pub fn apply_scenario(&self, id: ScenarioId) {
        self.runtime
            .cmd_tx
            .send(SimCommand::ApplyScenario(id))
            .expect("failed to apply scenario");
        self.wait_until(Duration::from_secs(2), || {
            let state = self.runtime.tui_state.lock().unwrap();
            state.traces.is_empty() && state.next_trace_id == 1
        });
    }

    pub fn send_message(
        &self,
        from: usize,
        to: usize,
        kind: MessageKind,
        body: impl Into<String>,
    ) -> u64 {
        let prev_len = self.state().traces.len();
        self.runtime
            .cmd_tx
            .send(SimCommand::SendMessage {
                from,
                to,
                kind,
                body: body.into(),
            })
            .expect("failed to send message command");

        self.wait_for_trace_count(prev_len + 1, Duration::from_secs(2));
        self.state()
            .traces
            .back()
            .map(|trace| trace.id)
            .expect("expected trace to exist after send")
    }

    pub fn inject_message_with_id(
        &self,
        from: usize,
        to: usize,
        kind: MessageKind,
        body: impl Into<String>,
        message_id: [u8; 8],
    ) -> u64 {
        self.inject_message_with_id_and_ttl(from, to, kind, body, message_id, DEFAULT_TTL)
    }

    pub fn inject_message_with_id_and_ttl(
        &self,
        from: usize,
        to: usize,
        kind: MessageKind,
        body: impl Into<String>,
        message_id: [u8; 8],
        ttl: u8,
    ) -> u64 {
        let body = body.into();
        let is_broadcast = to == BROADCAST_NODE;
        let destination_idx = if is_broadcast { from } else { to };
        let cfg = self.config();
        let source_caps = cfg.capabilities[from];
        let target_caps = if is_broadcast {
            0
        } else {
            cfg.capabilities[destination_idx]
        };
        let dst_addr = if is_broadcast {
            BROADCAST_ADDR
        } else {
            self.runtime.node_infos[destination_idx].short_addr
        };
        let link_enabled_at_send = if is_broadcast {
            true
        } else {
            cfg.link_enabled[from][destination_idx]
        };
        let drop_prob_at_send = if is_broadcast {
            0
        } else {
            cfg.drop_prob[from][destination_idx]
        };

        let trace_id = {
            let mut state = self.runtime.tui_state.lock().unwrap();
            state.create_trace(
                from,
                to,
                kind,
                body,
                source_caps,
                target_caps,
                PACKET_TYPE_DATA,
                if is_broadcast {
                    routing_core::protocol::packet::FLAG_BROADCAST
                } else {
                    0
                },
                dst_addr,
                is_broadcast,
                link_enabled_at_send,
                drop_prob_at_send,
                message_id,
                ttl,
            )
        };

        let msg = crate::medium::SimDataMessage {
            trace_id,
            from_idx: from,
            to_idx: to,
            is_broadcast,
            sender_idx: from,
            message_id,
            ttl,
            hop_count: 0,
        };

        pollster::block_on(async {
            self.runtime.medium.msg_inbox[from].send(msg).await;
        });

        trace_id
    }

    pub fn wait_for_trace_terminal(&self, trace_id: u64, timeout: Duration) -> MessageTrace {
        self.wait_until(timeout, || {
            self.state()
                .traces
                .iter()
                .find(|trace| trace.id == trace_id)
                .map(|trace| trace.terminal_status != TraceStatus::Pending)
                .unwrap_or(false)
        });

        self.trace(trace_id)
            .expect("trace should exist after reaching terminal state")
    }

    pub fn wait_for_trace_count(&self, expected: usize, timeout: Duration) {
        self.wait_until(timeout, || self.state().traces.len() >= expected);
    }

    pub fn seed_retained_delivery(
        &self,
        trace_id: u64,
        from_idx: usize,
        to_idx: usize,
        holder_idx: usize,
        owner_router_idx: usize,
        body: impl Into<String>,
    ) {
        let now_secs = self.runtime.tui_state.lock().unwrap().elapsed_secs;
        self.runtime
            .store_forward_state
            .lock()
            .unwrap()
            .retain_replica(RetainedMessage {
                trace_id,
                message_id: trace_id.to_le_bytes(),
                source_addr: self.runtime.node_infos[from_idx].short_addr,
                destination_addr: self.runtime.node_infos[to_idx].short_addr,
                holder_addr: self.runtime.node_infos[holder_idx].short_addr,
                owner_router_addr: self.runtime.node_infos[owner_router_idx].short_addr,
                body: retained_body_from_bytes(body.into().as_bytes()),
                enqueued_at_secs: now_secs,
                announced: false,
            });
    }

    pub fn run_initiator_h2h_once(&self, node_idx: usize) {
        let mut initiator = SimInitiator::new(
            node_idx,
            self.runtime.medium,
            self.runtime.node_infos,
            self.runtime.sim_config.clone(),
        );
        pollster::block_on(async {
            let capabilities = self.runtime.sim_config.lock().unwrap().capabilities[node_idx];
            run_shared_initiator_h2h_once(
                &mut initiator,
                &self.runtime.identities[node_idx],
                capabilities,
                &self.runtime.routing_tables[node_idx],
                &self.runtime.uptimes[node_idx],
            )
            .await;
        });
    }

    pub fn run_h2h_session_with_peer(&self, initiator_idx: usize, peer_idx: usize) -> bool {
        let mut initiator = SimInitiator::new(
            initiator_idx,
            self.runtime.medium,
            self.runtime.node_infos,
            self.runtime.sim_config.clone(),
        );
        pollster::block_on(async {
            let capabilities = self.runtime.sim_config.lock().unwrap().capabilities[initiator_idx];
            let peer_short = self.runtime.node_infos[peer_idx].short_addr;
            let peer_mac = self.runtime.node_infos[peer_idx].mac;
            let payload = build_h2h_payload(
                &self.runtime.identities[initiator_idx],
                capabilities,
                &self.runtime.uptimes[initiator_idx],
                &self.runtime.routing_tables[initiator_idx],
                &peer_short,
            )
            .await;

            let Ok(peer_payload) = initiator
                .initiate_h2h(TransportAddr::ble(peer_mac), &payload)
                .await
            else {
                let _ = initiator.finish_h2h_session().await;
                return false;
            };
            {
                let transport = TransportAddr::ble(peer_mac);
                let mut table = self.runtime.routing_tables[initiator_idx].lock().await;
                table.update_peer_from_h2h(
                    &peer_payload,
                    peer_short,
                    transport,
                    embassy_time::Instant::now().as_ticks(),
                );
            }

            let now_secs = self.runtime.tui_state.lock().unwrap().elapsed_secs;
            let mut backend =
                SharedStoreForwardBackend::new(self.runtime.store_forward_state.clone());
            let mut observer = HarnessObserver {
                tui_state: &self.runtime.tui_state,
            };
            run_initiator_store_forward_followups(
                &mut initiator,
                &self.runtime.identities[initiator_idx],
                capabilities,
                &self.runtime.routing_tables[initiator_idx],
                peer_short,
                &mut backend,
                &mut observer,
                now_secs,
            )
            .await;

            let _ = initiator.finish_h2h_session().await;
            true
        })
    }

    pub fn run_lpn_wake_without_delivery_ack(&self, initiator_idx: usize, peer_idx: usize) -> bool {
        let mut initiator = SimInitiator::new(
            initiator_idx,
            self.runtime.medium,
            self.runtime.node_infos,
            self.runtime.sim_config.clone(),
        );
        pollster::block_on(async {
            let capabilities = self.runtime.sim_config.lock().unwrap().capabilities[initiator_idx];
            let peer_short = self.runtime.node_infos[peer_idx].short_addr;
            let peer_mac = self.runtime.node_infos[peer_idx].mac;
            let payload = build_h2h_payload(
                &self.runtime.identities[initiator_idx],
                capabilities,
                &self.runtime.uptimes[initiator_idx],
                &self.runtime.routing_tables[initiator_idx],
                &peer_short,
            )
            .await;

            let Ok(peer_payload) = initiator
                .initiate_h2h(TransportAddr::ble(peer_mac), &payload)
                .await
            else {
                let _ = initiator.finish_h2h_session().await;
                return false;
            };
            {
                let transport = TransportAddr::ble(peer_mac);
                let mut table = self.runtime.routing_tables[initiator_idx].lock().await;
                table.update_peer_from_h2h(
                    &peer_payload,
                    peer_short,
                    transport,
                    embassy_time::Instant::now().as_ticks(),
                );
            }

            loop {
                match with_timeout(
                    embassy_time::Duration::from_millis(500),
                    initiator.receive_h2h_frame(),
                )
                .await
                {
                    Ok(Ok(H2hFrame::DeliverySummary { pending_count, .. })) => {
                        if pending_count == 0 {
                            continue;
                        }
                    }
                    Ok(Ok(H2hFrame::DeliveryData { trace_id, .. })) => {
                        self.runtime.tui_state.lock().unwrap().push_trace_event(
                            trace_id,
                            initiator_idx,
                            0,
                            0,
                            TraceEventKind::LpnWakeSync {
                                router_node: peer_idx,
                            },
                            format!(
                                "LPN {} woke router {} for delayed-delivery sync (ack intentionally withheld)",
                                initiator_idx, peer_idx
                            ),
                        );
                        self.runtime.tui_state.lock().unwrap().push_trace_event(
                            trace_id,
                            initiator_idx,
                            0,
                            0,
                            TraceEventKind::DeliveredFromStore {
                                router_node: peer_idx,
                            },
                            format!(
                                "LPN {} received retained delivery from router {} without sending ack",
                                initiator_idx, peer_idx
                            ),
                        );
                        self.runtime
                            .tui_state
                            .lock()
                            .unwrap()
                            .mark_trace_delivered(trace_id);
                        let _ = initiator.send_h2h_frame(&H2hFrame::SessionDone).await;
                    }
                    Ok(Ok(H2hFrame::SessionDone)) => break,
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) | Err(_) => break,
                }
            }

            let _ = initiator.finish_h2h_session().await;
            true
        })
    }

    pub fn trace_event_count(
        &self,
        trace_id: u64,
        predicate: impl Fn(&TraceEventKind) -> bool,
    ) -> usize {
        self.trace(trace_id)
            .map(|trace| {
                trace
                    .events
                    .iter()
                    .filter(|event| predicate(&event.kind))
                    .count()
            })
            .unwrap_or(0)
    }

    pub fn trace(&self, trace_id: u64) -> Option<MessageTrace> {
        self.state()
            .traces
            .iter()
            .find(|trace| trace.id == trace_id)
            .cloned()
    }

    pub fn trace_terminal_status(&self, trace_id: u64) -> Option<TraceStatus> {
        self.trace(trace_id).map(|trace| trace.terminal_status)
    }

    pub fn forwarded_edges(&self, trace_id: u64) -> Vec<(usize, usize)> {
        self.trace(trace_id)
            .map(|trace| {
                trace
                    .events
                    .iter()
                    .filter_map(|event| match event.kind {
                        TraceEventKind::Forwarded { to_node } => Some((event.node_idx, to_node)),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn retained_trace_exists_at_holder(&self, trace_id: u64, holder_idx: usize) -> bool {
        self.runtime
            .store_forward_state
            .lock()
            .unwrap()
            .contains_trace_at_holder(trace_id, self.runtime.node_infos[holder_idx].short_addr)
    }

    pub fn wait_for_retained_trace_at_holder(
        &self,
        trace_id: u64,
        holder_idx: usize,
        timeout: Duration,
    ) {
        self.wait_until(timeout, || {
            self.retained_trace_exists_at_holder(trace_id, holder_idx)
        });
    }

    pub fn trace_has_delivery(&self, trace_id: u64, node_idx: usize) -> bool {
        self.trace(trace_id)
            .map(|trace| {
                trace.events.iter().any(|event| {
                    matches!(event.kind, TraceEventKind::Delivered) && event.node_idx == node_idx
                })
            })
            .unwrap_or(false)
    }

    pub fn trace_has_blocked_edge(&self, trace_id: u64, from: usize, to: usize) -> bool {
        self.trace(trace_id)
            .map(|trace| {
                trace.events.iter().any(|event| {
                    matches!(event.kind, TraceEventKind::Blocked { to_node } if to_node == to)
                        && event.node_idx == from
                })
            })
            .unwrap_or(false)
    }

    pub fn broadcast_observers(&self, trace_id: u64) -> Vec<usize> {
        let mut observers = Vec::new();
        if let Some(trace) = self.trace(trace_id) {
            for event in &trace.events {
                if matches!(event.kind, TraceEventKind::ObservedBroadcast)
                    && !observers.contains(&event.node_idx)
                {
                    observers.push(event.node_idx);
                }
            }
        }
        observers
    }

    pub fn assert_terminal_status_one_of(&self, trace_id: u64, expected: &[TraceStatus]) {
        let actual = self
            .trace_terminal_status(trace_id)
            .unwrap_or_else(|| panic!("missing trace {trace_id} when checking terminal status"));
        assert!(
            expected.contains(&actual),
            "trace {} terminal status {:?} not in expected set {:?}",
            trace_id,
            actual,
            expected
        );
    }

    pub fn assert_forwarded_edges(&self, trace_id: u64, expected: &[(usize, usize)]) {
        let actual = self.forwarded_edges(trace_id);
        assert_eq!(
            actual, expected,
            "trace {} forwarded edge path mismatch",
            trace_id
        );
    }

    pub fn assert_delivered_to(&self, trace_id: u64, node_idx: usize) {
        assert!(
            self.trace_has_delivery(trace_id, node_idx),
            "trace {} never delivered at node {}",
            trace_id,
            node_idx
        );
    }

    pub fn assert_blocked_edge(&self, trace_id: u64, from: usize, to: usize) {
        assert!(
            self.trace_has_blocked_edge(trace_id, from, to),
            "trace {} never recorded blocked edge {} -> {}",
            trace_id,
            from,
            to
        );
    }

    pub fn assert_broadcast_observed_by_at_least(&self, trace_id: u64, min_count: usize) {
        let count = self.broadcast_observers(trace_id).len();
        assert!(
            count >= min_count,
            "trace {} broadcast observed by {} nodes, expected at least {}",
            trace_id,
            count,
            min_count
        );
    }

    pub fn seed_all_direct_links(&self) {
        let cfg = self.config();
        for from in 0..cfg.n_active {
            for to in 0..cfg.n_active {
                if from == to || !cfg.link_enabled[from][to] {
                    continue;
                }
                self.seed_direct_peer(from, to, 1);
            }
        }
    }

    pub fn seed_direct_peer(&self, from: usize, to: usize, now_ticks: u64) {
        let cfg = self.config();
        let short_addr = self.runtime.node_infos[to].short_addr;
        let capabilities = cfg.capabilities[to];
        let transport = TransportAddr::ble(self.runtime.node_infos[to].mac);
        with_routing_table(&self.runtime.routing_tables[from], |table| {
            table.update_peer_compact(short_addr, capabilities, transport, now_ticks);
        });
    }

    pub fn seed_indirect_peer_via(
        &self,
        from: usize,
        via: usize,
        to: usize,
        hop_count: u8,
        now_ticks: u64,
    ) {
        let cfg = self.config();
        self.seed_direct_peer(from, via, now_ticks);

        const NONE: Option<PeerInfo> = None;
        let mut peers = [NONE; routing_core::config::H2H_MAX_PEER_ENTRIES];
        peers[0] = Some(PeerInfo {
            pubkey: self.runtime.identities[to].pubkey(),
            capabilities: cfg.capabilities[to],
            hop_count: hop_count.saturating_sub(1),
        });

        let payload = H2hPayload {
            full_pubkey: Some(self.runtime.identities[via].pubkey()),
            capabilities: cfg.capabilities[via],
            uptime_secs: 1,
            peers,
            peer_count: 1,
        };

        let transport = TransportAddr::ble(self.runtime.node_infos[via].mac);
        let partner = self.runtime.node_infos[via].short_addr;
        with_routing_table(&self.runtime.routing_tables[from], |table| {
            table.update_peer_from_h2h(&payload, partner, transport, now_ticks);
        });
    }

    fn wait_until(&self, timeout: Duration, predicate: impl Fn() -> bool) {
        let deadline = Instant::now() + timeout;
        while Instant::now() <= deadline {
            if predicate() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "timed out waiting for simulator condition after {:?}",
            timeout
        );
    }
}

fn with_routing_table(
    table: &'static AsyncMutex<CriticalSectionRawMutex, RoutingTable>,
    f: impl FnOnce(&mut RoutingTable),
) {
    pollster::block_on(async {
        let mut table = table.lock().await;
        f(&mut table);
    });
}

#[allow(dead_code)]
pub const BROADCAST_NODE: usize = MAX_NODES;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_ops;
    use crate::scenario;
    use crate::sim_state::TraceStatus;

    #[test]
    fn routed_message_forwards_across_seeded_indirect_path() {
        let harness = SimHarness::new(scenario::full_mesh_small(3));
        harness.update_config(|cfg| {
            for from in 0..3 {
                for to in 0..3 {
                    config_ops::set_link_enabled(cfg, from, to, false);
                    cfg.drop_prob[from][to] = 0;
                }
            }
            config_ops::set_bidirectional_link(cfg, 0, 1, true);
            config_ops::set_bidirectional_link(cfg, 1, 2, true);
        });

        harness.seed_direct_peer(0, 1, 1);
        harness.seed_direct_peer(1, 0, 1);
        harness.seed_direct_peer(1, 2, 1);
        harness.seed_direct_peer(2, 1, 1);
        harness.seed_indirect_peer_via(0, 1, 2, 1, 1);

        let trace_id = harness.send_message(0, 2, MessageKind::Manual, "hello mesh");
        let trace = harness.wait_for_trace_terminal(trace_id, Duration::from_secs(2));

        assert_eq!(trace.terminal_status, TraceStatus::Delivered);
        harness.assert_forwarded_edges(trace_id, &[(0, 1), (1, 2)]);
        harness.assert_delivered_to(trace_id, 2);
    }

    #[test]
    fn routed_message_expires_when_ttl_too_small_for_indirect_hop() {
        let harness = SimHarness::new(scenario::full_mesh_small(3));
        harness.update_config(|cfg| {
            for from in 0..3 {
                for to in 0..3 {
                    config_ops::set_link_enabled(cfg, from, to, false);
                    cfg.drop_prob[from][to] = 0;
                }
            }
            config_ops::set_bidirectional_link(cfg, 0, 1, true);
            config_ops::set_bidirectional_link(cfg, 1, 2, true);
        });

        harness.seed_direct_peer(0, 1, 1);
        harness.seed_direct_peer(1, 0, 1);
        harness.seed_direct_peer(1, 2, 1);
        harness.seed_direct_peer(2, 1, 1);
        harness.seed_indirect_peer_via(0, 1, 2, 1, 1);

        let trace_id = harness.inject_message_with_id_and_ttl(
            0,
            2,
            MessageKind::Manual,
            "ttl test",
            [0xAA; 8],
            1,
        );
        let trace = harness.wait_for_trace_terminal(trace_id, Duration::from_secs(2));

        assert_eq!(trace.terminal_status, TraceStatus::TtlExpired);
        harness.assert_forwarded_edges(trace_id, &[(0, 1)]);
    }

    #[test]
    fn routed_duplicate_message_ids_are_suppressed() {
        let harness = SimHarness::new(scenario::full_mesh_small(2));
        harness.update_config(|cfg| {
            for from in 0..2 {
                for to in 0..2 {
                    cfg.drop_prob[from][to] = 0;
                }
            }
        });

        harness.seed_direct_peer(0, 1, 1);
        harness.seed_direct_peer(1, 0, 1);

        let message_id = [0x44; 8];
        let first = harness.inject_message_with_id(0, 1, MessageKind::Manual, "first", message_id);
        let second =
            harness.inject_message_with_id(0, 1, MessageKind::Manual, "second", message_id);

        let first_trace = harness.wait_for_trace_terminal(first, Duration::from_secs(2));
        let second_trace = harness.wait_for_trace_terminal(second, Duration::from_secs(2));

        assert_eq!(first_trace.terminal_status, TraceStatus::Delivered);
        assert_eq!(second_trace.terminal_status, TraceStatus::Deduped);
        harness.assert_delivered_to(first, 1);
    }
}
