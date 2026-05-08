//! Shared types between the embassy simulator thread and the TUI main thread.

use std::collections::VecDeque;

use routing_core::node::roles::Capabilities;

pub const MAX_NODES: usize = 20;
pub const DEFAULT_NODES: usize = 12;

// ── NodeType ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum NodeType {
    #[default]
    FullNode,
    Router,
    Sensor,
    Gateway,
}

impl NodeType {
    #[allow(dead_code)]
    pub fn cycle(self) -> Self {
        match self {
            NodeType::FullNode => NodeType::Router,
            NodeType::Router => NodeType::Sensor,
            NodeType::Sensor => NodeType::Gateway,
            NodeType::Gateway => NodeType::FullNode,
        }
    }

    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            NodeType::FullNode => "Router+App",
            NodeType::Router => "Router",
            NodeType::Sensor => "Sensor",
            NodeType::Gateway => "Gateway",
        }
    }
}

// ── MessageKind ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
#[allow(dead_code)]
pub enum MessageKind {
    Manual,
    Temperature,
    Humidity,
}

impl MessageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MessageKind::Manual => "manual",
            MessageKind::Temperature => "temp",
            MessageKind::Humidity => "humidity",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TraceStatus {
    Pending,
    Delivered,
    NoRoute,
    TtlExpired,
    Dropped,
    Deduped,
}

impl TraceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TraceStatus::Pending => "pending",
            TraceStatus::Delivered => "delivered",
            TraceStatus::NoRoute => "no-route",
            TraceStatus::TtlExpired => "ttl-expired",
            TraceStatus::Dropped => "dropped",
            TraceStatus::Deduped => "deduped",
        }
    }
}

#[derive(Clone)]
pub enum TraceEventKind {
    Queued,
    Deferred,
    Received { from_node: usize },
    ObservedBroadcast,
    Forwarded { to_node: usize },
    LpnWakeSync { router_node: usize },
    PendingAnnounced { count: usize },
    DeliveredFromStore { router_node: usize },
    DeliveryConfirmed { lpn_node: usize },
    ExpiredFromStore,
    Delivered,
    Dropped { to_node: Option<usize> },
    Blocked { to_node: usize },
    NoRoute,
    Deduped,
    TtlExpired,
}

impl TraceEventKind {
    pub fn describe(&self, node_idx: usize, ttl: u8, hop_count: u8) -> String {
        match self {
            TraceEventKind::Queued => format!(
                "node {} queued packet locally (ttl={}, hop={})",
                node_idx, ttl, hop_count
            ),
            TraceEventKind::Deferred => format!(
                "node {} retained packet for delayed delivery (ttl={}, hop={})",
                node_idx, ttl, hop_count
            ),
            TraceEventKind::Received { from_node } => format!(
                "node {} received packet from {} (ttl={}, hop={})",
                node_idx, from_node, ttl, hop_count
            ),
            TraceEventKind::ObservedBroadcast => {
                format!(
                    "node {} observed broadcast (ttl={}, hop={})",
                    node_idx, ttl, hop_count
                )
            }
            TraceEventKind::Forwarded { to_node } => format!(
                "node {} forwarded packet to {} (ttl={}, hop={})",
                node_idx, to_node, ttl, hop_count
            ),
            TraceEventKind::LpnWakeSync { router_node } => format!(
                "node {} woke router {} for delayed-delivery sync (ttl={}, hop={})",
                node_idx, router_node, ttl, hop_count
            ),
            TraceEventKind::PendingAnnounced { count } => format!(
                "node {} announced {} pending deliveries (ttl={}, hop={})",
                node_idx, count, ttl, hop_count
            ),
            TraceEventKind::DeliveredFromStore { router_node } => format!(
                "node {} received retained packet from router {} (ttl={}, hop={})",
                node_idx, router_node, ttl, hop_count
            ),
            TraceEventKind::DeliveryConfirmed { lpn_node } => format!(
                "node {} confirmed retained delivery to {} (ttl={}, hop={})",
                node_idx, lpn_node, ttl, hop_count
            ),
            TraceEventKind::ExpiredFromStore => format!(
                "node {} expired retained delivery (ttl={}, hop={})",
                node_idx, ttl, hop_count
            ),
            TraceEventKind::Delivered => format!(
                "node {} delivered packet locally (ttl={}, hop={})",
                node_idx, ttl, hop_count
            ),
            TraceEventKind::Dropped { to_node } => match to_node {
                Some(to_node) => format!(
                    "node {} dropped packet on edge to {} (ttl={}, hop={})",
                    node_idx, to_node, ttl, hop_count
                ),
                None => format!(
                    "node {} dropped packet (ttl={}, hop={})",
                    node_idx, ttl, hop_count
                ),
            },
            TraceEventKind::Blocked { to_node } => format!(
                "node {} blocked edge to {} (ttl={}, hop={})",
                node_idx, to_node, ttl, hop_count
            ),
            TraceEventKind::NoRoute => format!(
                "node {} found no route (ttl={}, hop={})",
                node_idx, ttl, hop_count
            ),
            TraceEventKind::Deduped => format!(
                "node {} rejected duplicate packet (ttl={}, hop={})",
                node_idx, ttl, hop_count
            ),
            TraceEventKind::TtlExpired => format!(
                "node {} hit ttl expiry (ttl={}, hop={})",
                node_idx, ttl, hop_count
            ),
        }
    }
}

#[derive(Clone)]
pub struct TraceEvent {
    pub time_secs: u32,
    pub node_idx: usize,
    pub ttl: u8,
    pub hop_count: u8,
    pub kind: TraceEventKind,
    pub message: String,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TraceFilter {
    All,
    Directed,
    Broadcast,
}

impl TraceFilter {
    pub fn as_str(self) -> &'static str {
        match self {
            TraceFilter::All => "all",
            TraceFilter::Directed => "directed",
            TraceFilter::Broadcast => "broadcast",
        }
    }
}

// ── Snapshots (written by embassy, read by TUI) ───────────────────────────────

#[derive(Clone, Default)]
pub struct PeerSnapshot {
    pub short_addr: [u8; 8],
    pub trust: u8,
    pub hop_count: u8,
}

#[derive(Clone, Default)]
pub struct NodeSnapshot {
    pub active: bool,
    pub short_addr: [u8; 8],
    pub uptime_secs: u32,
    pub capabilities: u16,
    #[allow(dead_code)]
    pub node_type: NodeType,
    pub peers: heapless::Vec<PeerSnapshot, 32>,
}

#[derive(Clone)]
pub struct MessageTrace {
    pub id: u64,
    pub created_secs: u32,
    pub delivered_secs: Option<u32>,
    pub from_idx: usize,
    /// `MAX_NODES` means broadcast.
    pub to_idx: usize,
    pub kind: MessageKind,
    pub body: String,
    pub source_caps: u16,
    pub target_caps: u16,
    pub packet_type: u8,
    pub packet_flags: u8,
    pub dst_addr: [u8; 8],
    pub is_broadcast: bool,
    pub link_enabled_at_send: bool,
    pub drop_prob_at_send: u8,
    pub message_id: [u8; 8],
    pub ttl_at_send: u8,
    pub terminal_status: TraceStatus,
    pub events: Vec<TraceEvent>,
}

#[derive(Clone)]
pub struct TuiState {
    pub node_short_addrs: [[u8; 8]; MAX_NODES],
    pub nodes: [NodeSnapshot; MAX_NODES],
    /// Capped at 200 entries.
    pub traces: VecDeque<MessageTrace>,
    pub elapsed_secs: u32,
    pub next_trace_id: u64,
    pub msgs_sent: [u32; MAX_NODES],
    pub msgs_received: [u32; MAX_NODES],
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            node_short_addrs: [[0u8; 8]; MAX_NODES],
            nodes: core::array::from_fn(|_| NodeSnapshot::default()),
            traces: VecDeque::new(),
            elapsed_secs: 0,
            next_trace_id: 1,
            msgs_sent: [0; MAX_NODES],
            msgs_received: [0; MAX_NODES],
        }
    }
}

impl TuiState {
    pub fn create_trace(
        &mut self,
        from_idx: usize,
        to_idx: usize,
        kind: MessageKind,
        body: String,
        source_caps: u16,
        target_caps: u16,
        packet_type: u8,
        packet_flags: u8,
        dst_addr: [u8; 8],
        is_broadcast: bool,
        link_enabled_at_send: bool,
        drop_prob_at_send: u8,
        message_id: [u8; 8],
        ttl_at_send: u8,
    ) -> u64 {
        let id = self.next_trace_id;
        self.next_trace_id = self.next_trace_id.saturating_add(1);

        if self.traces.len() >= 200 {
            self.traces.pop_front();
        }

        self.traces.push_back(MessageTrace {
            id,
            created_secs: self.elapsed_secs,
            delivered_secs: None,
            from_idx,
            to_idx,
            kind,
            body,
            source_caps,
            target_caps,
            packet_type,
            packet_flags,
            dst_addr,
            is_broadcast,
            link_enabled_at_send,
            drop_prob_at_send,
            message_id,
            ttl_at_send,
            terminal_status: TraceStatus::Pending,
            events: vec![TraceEvent {
                time_secs: self.elapsed_secs,
                node_idx: from_idx,
                ttl: ttl_at_send,
                hop_count: 0,
                kind: TraceEventKind::Queued,
                message: if is_broadcast {
                    format!("trace created for {} → broadcast", from_idx)
                } else {
                    format!("trace created for {} → {}", from_idx, to_idx)
                },
            }],
        });

        id
    }

    pub fn mark_trace_delivered(&mut self, trace_id: u64) {
        let now = self.elapsed_secs;
        if let Some(trace) = self.traces.iter_mut().find(|trace| trace.id == trace_id) {
            trace.delivered_secs = Some(now);
            trace.terminal_status = TraceStatus::Delivered;
        }
    }

    pub fn push_trace_event(
        &mut self,
        trace_id: u64,
        node_idx: usize,
        ttl: u8,
        hop_count: u8,
        kind: TraceEventKind,
        message: impl Into<String>,
    ) {
        let now = self.elapsed_secs;
        if let Some(trace) = self.traces.iter_mut().find(|trace| trace.id == trace_id) {
            trace.events.push(TraceEvent {
                time_secs: now,
                node_idx,
                ttl,
                hop_count,
                kind,
                message: message.into(),
            });
        }
    }

    pub fn filtered_trace_indices(&self, filter: TraceFilter) -> Vec<usize> {
        self.traces
            .iter()
            .enumerate()
            .filter(|(_, trace)| match filter {
                TraceFilter::All => true,
                TraceFilter::Directed => !trace.is_broadcast,
                TraceFilter::Broadcast => trace.is_broadcast,
            })
            .map(|(idx, _)| idx)
            .collect()
    }

    pub fn set_trace_terminal_status(&mut self, trace_id: u64, status: TraceStatus) {
        if let Some(trace) = self.traces.iter_mut().find(|trace| trace.id == trace_id) {
            if trace.terminal_status != TraceStatus::Delivered {
                trace.terminal_status = status;
            }
        }
    }

    pub fn reset_runtime(&mut self) {
        self.traces.clear();
        self.elapsed_secs = 0;
        self.next_trace_id = 1;
        self.msgs_sent = [0; MAX_NODES];
        self.msgs_received = [0; MAX_NODES];
        self.nodes = core::array::from_fn(|i| NodeSnapshot {
            short_addr: self.node_short_addrs[i],
            ..NodeSnapshot::default()
        });
    }

    pub fn resolve_node_index(&self, short_addr: &[u8; 8]) -> Option<usize> {
        self.node_short_addrs
            .iter()
            .position(|addr| addr == short_addr)
    }
}

// ── SimConfig (written by TUI, read by embassy) ───────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct NodeBehavior {
    pub advertise: bool,
    pub scan: bool,
    pub initiate_h2h: bool,
    pub respond_h2h: bool,
    pub emit_sensor: bool,
}

impl Default for NodeBehavior {
    fn default() -> Self {
        Self {
            advertise: true,
            scan: true,
            initiate_h2h: true,
            respond_h2h: true,
            emit_sensor: true,
        }
    }
}

#[derive(Clone)]
pub struct SimConfig {
    pub n_active: usize,
    /// Whether a direct link exists between node a and node b.
    pub link_enabled: [[bool; MAX_NODES]; MAX_NODES],
    /// Simulated packet drop probability (0–100 %) per directed pair.
    pub drop_prob: [[u8; MAX_NODES]; MAX_NODES],
    pub capabilities: [u16; MAX_NODES],
    pub node_types: [NodeType; MAX_NODES],
    pub node_behaviors: [NodeBehavior; MAX_NODES],
    pub sensor_auto: bool,
    pub sensor_interval_secs: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        let mut link_enabled = [[true; MAX_NODES]; MAX_NODES];
        for i in 0..MAX_NODES {
            link_enabled[i][i] = false;
        }
        Self {
            n_active: DEFAULT_NODES,
            link_enabled,
            drop_prob: [[0u8; MAX_NODES]; MAX_NODES],
            capabilities: core::array::from_fn(|_| {
                Capabilities(Capabilities::ROUTE | Capabilities::APPLICATION).0
            }),
            node_types: core::array::from_fn(|_| NodeType::default()),
            node_behaviors: core::array::from_fn(|_| NodeBehavior::default()),
            sensor_auto: false,
            sensor_interval_secs: 5,
        }
    }
}

// ── SimCommand (sent from TUI to embassy via mpsc) ────────────────────────────

pub enum SimCommand {
    SendMessage {
        from: usize,
        to: usize,
        kind: MessageKind,
        body: String,
    },
    #[allow(dead_code)]
    AddNode,
    #[allow(dead_code)]
    RemoveNode(usize),
    ApplyScenario(crate::scenario::ScenarioId),
}
