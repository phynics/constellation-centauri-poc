use routing_core::crypto::identity::{PubKey, ShortAddr};
use routing_core::node::roles::Capabilities;

use crate::node::storage::LocalNodeRecord;
use crate::onboarding::marker_summary;

#[derive(Clone)]
pub struct LocalNodeView {
    pub short_addr: ShortAddr,
    pub pubkey: PubKey,
    pub authority_pubkey: PubKey,
    pub capabilities: u16,
    pub protocol_signature: String,
    pub network_marker: String,
    pub storage_dir: String,
}

#[derive(Clone)]
pub struct DiscoveredPeer {
    pub id: String,
    pub name: Option<String>,
    pub rssi: Option<i16>,
    pub last_seen_unix_secs: u64,
    pub has_onboarding_service: bool,
    pub has_constellation_signature: bool,
    pub onboarding_ready: bool,
    pub network_pubkey_hex: Option<String>,
    pub node_pubkey_hex: Option<String>,
    pub capabilities: Option<u16>,
    pub last_error: Option<String>,
}

#[derive(Clone)]
pub struct RoutingPeerView {
    pub short_addr: ShortAddr,
    pub capabilities: u16,
    pub trust: u8,
    pub hop_count: u8,
    pub last_seen_ticks: u64,
    pub transport_len: u8,
}

pub struct SharedState {
    pub local: LocalNodeView,
    pub scanning: bool,
    pub advertising: bool,
    pub peers: Vec<DiscoveredPeer>,
    pub routing_peers: Vec<RoutingPeerView>,
    pub uptime_secs: u32,
    pub events: Vec<String>,
}

impl SharedState {
    pub fn new(local_node: &LocalNodeRecord) -> Self {
        Self {
            local: LocalNodeView {
                short_addr: local_node.short_addr,
                pubkey: local_node.pubkey,
                authority_pubkey: local_node.authority_pubkey,
                capabilities: local_node.capabilities,
                protocol_signature: String::from_utf8_lossy(&local_node.protocol_signature)
                    .into_owned(),
                network_marker: marker_summary(&local_node.network_marker),
                storage_dir: local_node.storage_dir.display().to_string(),
            },
            scanning: false,
            advertising: false,
            peers: Vec::new(),
            routing_peers: Vec::new(),
            uptime_secs: 0,
            events: vec!["Companion started".to_string()],
        }
    }

    pub fn push_event(&mut self, event: impl Into<String>) {
        self.events.push(event.into());
        if self.events.len() > 256 {
            let drain = self.events.len() - 256;
            self.events.drain(0..drain);
        }
    }

    pub fn upsert_peer(&mut self, peer: DiscoveredPeer) {
        match self
            .peers
            .iter_mut()
            .find(|existing| existing.id == peer.id)
        {
            Some(existing) => {
                existing.name = peer.name;
                existing.rssi = peer.rssi;
                existing.last_seen_unix_secs = peer.last_seen_unix_secs;
                existing.has_onboarding_service = peer.has_onboarding_service;
            }
            None => self.peers.push(peer),
        }
        self.peers.sort_by(|a, b| a.id.cmp(&b.id));
    }

    pub fn update_peer_inspection(
        &mut self,
        id: String,
        has_constellation_signature: bool,
        onboarding_ready: bool,
        node_pubkey_hex: Option<String>,
        capabilities: Option<u16>,
    ) {
        if let Some(peer) = self.peers.iter_mut().find(|peer| peer.id == id) {
            peer.has_constellation_signature = has_constellation_signature;
            peer.onboarding_ready = onboarding_ready;
            peer.node_pubkey_hex = node_pubkey_hex;
            peer.capabilities = capabilities;
            peer.last_error = None;
        }
    }

    pub fn set_peer_network_pubkey(&mut self, id: String, network_pubkey_hex: String) {
        if let Some(peer) = self.peers.iter_mut().find(|peer| peer.id == id) {
            peer.network_pubkey_hex = Some(network_pubkey_hex);
            peer.onboarding_ready = false;
        }
    }

    pub fn set_peer_error(&mut self, id: String, error: String) {
        if let Some(peer) = self.peers.iter_mut().find(|peer| peer.id == id) {
            peer.last_error = Some(error);
        }
    }

    pub fn update_routing_snapshot(&mut self, uptime_secs: u32, peers: Vec<RoutingPeerView>) {
        self.uptime_secs = uptime_secs;
        self.routing_peers = peers;
    }
}

pub fn capability_summary(bits: u16) -> String {
    let mut parts = Vec::new();
    if bits & Capabilities::ROUTE != 0 {
        parts.push("ROUTE");
    }
    if bits & Capabilities::STORE != 0 {
        parts.push("STORE");
    }
    if bits & Capabilities::BRIDGE != 0 {
        parts.push("BRIDGE");
    }
    if bits & Capabilities::APPLICATION != 0 {
        parts.push("APP");
    }
    if bits & Capabilities::LOW_ENERGY != 0 {
        parts.push("LOW_ENERGY");
    }
    if bits & Capabilities::MOBILE != 0 {
        parts.push("MOBILE");
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join("|")
    }
}
