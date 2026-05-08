use std::time::{Duration, Instant};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;

use routing_core::protocol::h2h::{H2hPayload, PeerInfo};
use routing_core::routing::table::RoutingTable;
use routing_core::transport::TransportAddr;

use crate::config_ops;
use crate::runtime::SimRuntime;
use crate::scenario::ScenarioId;
use crate::sim_state::{
    MessageKind, MessageTrace, SimCommand, SimConfig, TraceEventKind, TraceStatus, TuiState,
    MAX_NODES,
};
use crate::store_forward::RetainedMessage;

pub struct SimHarness {
    runtime: SimRuntime,
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
                from_idx,
                to_idx,
                holder_idx,
                owner_router_idx,
                body: body.into(),
                enqueued_at_secs: now_secs,
                announced: false,
            });
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
