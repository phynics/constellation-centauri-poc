//! `SimResponder` and `SimInitiator` — in-process implementations of the
//! `H2hResponder` / `H2hInitiator` traits using `SimMedium` channels.
//!
//! Topology and packet-drop behaviour are driven by `SimConfig` at runtime,
//! so the TUI can toggle links and adjust drop probabilities on the fly.

use std::sync::{Arc, Mutex};

use heapless::Vec;
use embassy_time::{Duration, Timer};
use rand::Rng as _;

use routing_core::network::{
    DiscoveryEvent, H2hInitiator, H2hResponder, InboundH2h, MAX_SCAN_RESULTS, NetworkError,
};
use routing_core::protocol::h2h::H2hPayload;

use crate::medium::{
    deserialize_payload, serialize_payload, SimH2hRequest, SimH2hResponse, SimMedium,
};
use crate::sim_state::{SimConfig, MAX_NODES};

// ── Peer info shared across all sim nodes ─────────────────────────────────────

/// Static info about every simulated node, shared with all `SimInitiator`s.
pub struct SimNodeInfo {
    pub short_addr: [u8; 8],
    pub capabilities: u16,
    /// MAC used on the simulated medium.  Convention: `mac[0] = node_index`.
    pub mac: [u8; 6],
}

// ── SimResponder ──────────────────────────────────────────────────────────────

pub struct SimResponder {
    node_idx: usize,
    medium: &'static SimMedium,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
    pending_sender: Option<usize>,
}

impl SimResponder {
    pub fn new(
        node_idx: usize,
        medium: &'static SimMedium,
        all_nodes: &'static [SimNodeInfo; MAX_NODES],
    ) -> Self {
        Self { node_idx, medium, all_nodes, pending_sender: None }
    }
}

impl H2hResponder for SimResponder {
    async fn receive_h2h(&mut self) -> Result<InboundH2h, NetworkError> {
        let req = self.medium.h2h_req[self.node_idx].receive().await;

        let peer_payload = deserialize_payload(&req.payload_bytes, req.payload_len)
            .ok_or(NetworkError::ProtocolError)?;

        let peer_mac = self.all_nodes[req.sender_idx].mac;
        self.pending_sender = Some(req.sender_idx);

        Ok(InboundH2h { peer_mac, peer_payload })
    }

    async fn send_h2h_response(&mut self, payload: &H2hPayload) -> Result<(), NetworkError> {
        let sender_idx = self.pending_sender.take().ok_or(NetworkError::ProtocolError)?;

        let (bytes, len) = serialize_payload(payload).ok_or(NetworkError::ProtocolError)?;

        self.medium.h2h_resp[sender_idx]
            .send(SimH2hResponse { result: Ok((bytes, len)) })
            .await;

        Ok(())
    }
}

// ── SimInitiator ──────────────────────────────────────────────────────────────

pub struct SimInitiator {
    node_idx: usize,
    medium: &'static SimMedium,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
    sim_config: Arc<Mutex<SimConfig>>,
}

impl SimInitiator {
    pub fn new(
        node_idx: usize,
        medium: &'static SimMedium,
        all_nodes: &'static [SimNodeInfo; MAX_NODES],
        sim_config: Arc<Mutex<SimConfig>>,
    ) -> Self {
        Self { node_idx, medium, all_nodes, sim_config }
    }
}

impl H2hInitiator for SimInitiator {
    async fn scan(&mut self, duration_ms: u64) -> Vec<DiscoveryEvent, MAX_SCAN_RESULTS> {
        // Simulate scan latency.
        Timer::after(Duration::from_millis(duration_ms)).await;

        let config = self.sim_config.lock().unwrap();

        // Inactive nodes don't scan.
        if self.node_idx >= config.n_active {
            return Vec::new();
        }

        let mut results = Vec::new();
        for (i, node) in self.all_nodes.iter().enumerate() {
            if i == self.node_idx || i >= config.n_active {
                continue;
            }
            if !config.link_enabled[self.node_idx][i] {
                continue;
            }
            // Apply drop_prob to advertising packets too, so a dropped link
            // stops refreshing last_seen_ticks and trust decays naturally.
            let drop = config.drop_prob[self.node_idx][i];
            if drop > 0 && rand::thread_rng().gen_range(0u8..100) < drop {
                continue;
            }
            let _ = results.push(DiscoveryEvent {
                short_addr: node.short_addr,
                capabilities: node.capabilities,
                mac: node.mac,
            });
        }
        results
    }

    async fn initiate_h2h(
        &mut self,
        peer_mac: [u8; 6],
        our_payload: &H2hPayload,
    ) -> Result<H2hPayload, NetworkError> {
        // Convention: mac[0] = node_index in the simulator.
        let peer_idx = peer_mac[0] as usize;
        if peer_idx >= MAX_NODES {
            return Err(NetworkError::ConnectionFailed);
        }

        // Check config: inactive peer or simulated packet drop.
        {
            let config = self.sim_config.lock().unwrap();
            if peer_idx >= config.n_active {
                return Err(NetworkError::ConnectionFailed);
            }
            let drop = config.drop_prob[self.node_idx][peer_idx];
            if drop > 0 && rand::thread_rng().gen_range(0u8..100) < drop {
                return Err(NetworkError::ConnectionFailed);
            }
        }

        let (bytes, len) = serialize_payload(our_payload).ok_or(NetworkError::ProtocolError)?;

        // Push H2H request into peer's inbox.
        self.medium.h2h_req[peer_idx]
            .send(SimH2hRequest {
                sender_idx: self.node_idx,
                payload_bytes: bytes,
                payload_len: len,
            })
            .await;

        // Wait for response in our own response slot.
        let response = self.medium.h2h_resp[self.node_idx].receive().await;

        let (resp_bytes, resp_len) = response.result?;
        deserialize_payload(&resp_bytes, resp_len).ok_or(NetworkError::ProtocolError)
    }
}
