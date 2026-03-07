//! Shared types between the embassy simulator thread and the TUI main thread.

use std::collections::VecDeque;

pub const MAX_NODES: usize = 8;
pub const DEFAULT_NODES: usize = 5;

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
    pub fn cycle(self) -> Self {
        match self {
            NodeType::FullNode => NodeType::Router,
            NodeType::Router => NodeType::Sensor,
            NodeType::Sensor => NodeType::Gateway,
            NodeType::Gateway => NodeType::FullNode,
        }
    }

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
    #[allow(dead_code)]
    pub node_type: NodeType,
    pub peers: heapless::Vec<PeerSnapshot, 32>,
}

#[derive(Clone)]
pub struct MessageEntry {
    pub time_secs: u32,
    pub from_idx: usize,
    /// `MAX_NODES` means broadcast.
    pub to_idx: usize,
    pub kind: MessageKind,
    pub body: String,
}

pub struct TuiState {
    pub nodes: [NodeSnapshot; MAX_NODES],
    /// Capped at 200 entries.
    pub messages: VecDeque<MessageEntry>,
    pub elapsed_secs: u32,
    pub msgs_sent: [u32; MAX_NODES],
    pub msgs_received: [u32; MAX_NODES],
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            nodes: core::array::from_fn(|_| NodeSnapshot::default()),
            messages: VecDeque::new(),
            elapsed_secs: 0,
            msgs_sent: [0; MAX_NODES],
            msgs_received: [0; MAX_NODES],
        }
    }
}

impl TuiState {
    pub fn push_message(&mut self, entry: MessageEntry) {
        if self.messages.len() >= 200 {
            self.messages.pop_front();
        }
        self.messages.push_back(entry);
    }
}

// ── SimConfig (written by TUI, read by embassy) ───────────────────────────────

pub struct SimConfig {
    pub n_active: usize,
    /// Whether a direct link exists between node a and node b.
    pub link_enabled: [[bool; MAX_NODES]; MAX_NODES],
    /// Simulated packet drop probability (0–100 %) per directed pair.
    pub drop_prob: [[u8; MAX_NODES]; MAX_NODES],
    pub node_types: [NodeType; MAX_NODES],
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
            node_types: core::array::from_fn(|_| NodeType::default()),
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
    AddNode,
    RemoveNode(usize),
}
