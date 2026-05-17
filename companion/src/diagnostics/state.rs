//! Companion diagnostics state.
//!
//! Purpose: define the host-side views rendered by the companion UI for peers,
//! events, local identity, and network membership.
//!
//! Design decisions:
//! - Keep diagnostics/UI projection state in the companion crate so it does not
//!   become a second protocol model.
use routing_core::crypto::identity::{NetworkAddr, PubKey, ShortAddr};
use routing_core::node::roles::Capabilities;
use routing_core::routing::table::PeerEntry;

use crate::node::storage::LocalNodeRecord;
use crate::onboarding::marker_summary;

#[derive(Clone)]
pub struct LocalNodeView {
    pub short_addr: ShortAddr,
    pub pubkey: PubKey,
    pub authority_pubkey: PubKey,
    pub capabilities: Capabilities,
    pub protocol_signature: String,
    pub network_marker: String,
    pub storage_dir: String,
}

#[derive(Clone)]
pub struct DiscoveredPeer {
    pub id: String,
    pub short_addr: Option<ShortAddr>,
    pub name: Option<String>,
    pub rssi: Option<i16>,
    pub last_seen_unix_secs: u64,
    pub has_onboarding_service: bool,
    pub has_constellation_signature: bool,
    pub onboarding_ready: bool,
    pub network_pubkey_hex: Option<String>,
    pub network_addr: Option<NetworkAddr>,
    pub node_pubkey_hex: Option<String>,
    pub capabilities: Option<Capabilities>,
    pub last_error: Option<String>,
}

#[derive(Clone)]
pub struct RoutingPeerView {
    pub short_addr: ShortAddr,
    pub capabilities: Capabilities,
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

impl From<&LocalNodeRecord> for LocalNodeView {
    fn from(local_node: &LocalNodeRecord) -> Self {
        Self {
            short_addr: local_node.short_addr,
            pubkey: local_node.pubkey,
            authority_pubkey: local_node.authority_pubkey,
            capabilities: local_node.capabilities,
            protocol_signature: String::from_utf8_lossy(&local_node.protocol_signature).into_owned(),
            network_marker: marker_summary(&local_node.network_marker),
            storage_dir: local_node.storage_dir.display().to_string(),
        }
    }
}

impl From<&PeerEntry> for RoutingPeerView {
    fn from(peer: &PeerEntry) -> Self {
        Self {
            short_addr: peer.short_addr,
            capabilities: peer.capabilities.into(),
            trust: peer.trust,
            hop_count: peer.hop_count,
            last_seen_ticks: peer.last_seen_ticks,
            transport_len: peer.transport_addr.len,
        }
    }
}

impl DiscoveredPeer {
    pub fn from_scan_observation(
        id: String,
        name: Option<String>,
        rssi: Option<i16>,
        last_seen_unix_secs: u64,
        has_onboarding_service: bool,
        short_addr: Option<ShortAddr>,
        capabilities: Option<Capabilities>,
        network_addr: Option<NetworkAddr>,
        onboarding_ready: bool,
    ) -> Self {
        Self {
            id,
            short_addr,
            name,
            rssi,
            last_seen_unix_secs,
            has_onboarding_service,
            has_constellation_signature: false,
            onboarding_ready,
            network_pubkey_hex: None,
            network_addr,
            node_pubkey_hex: None,
            capabilities,
            last_error: None,
        }
    }
}

impl SharedState {
    pub fn new(local_node: &LocalNodeRecord) -> Self {
        Self {
            local: LocalNodeView::from(local_node),
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
                if peer.short_addr.is_some() {
                    existing.short_addr = peer.short_addr;
                }
                if peer.capabilities.is_some() {
                    existing.capabilities = peer.capabilities;
                }
                if peer.network_addr.is_some() {
                    existing.network_addr = peer.network_addr;
                }
                if peer.onboarding_ready {
                    existing.onboarding_ready = true;
                }
            }
            None => self.peers.push(peer),
        }
        self.peers.sort_by(|a, b| a.id.cmp(&b.id));
    }

    pub fn update_peer_inspection(
        &mut self,
        id: String,
        short_addr: Option<ShortAddr>,
        has_constellation_signature: bool,
        onboarding_ready: bool,
        node_pubkey_hex: Option<String>,
        capabilities: Option<Capabilities>,
    ) {
        if let Some(peer) = self.peers.iter_mut().find(|peer| peer.id == id) {
            peer.short_addr = short_addr;
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

    pub fn update_local_network_authority(
        &mut self,
        authority_pubkey: PubKey,
        network_marker: String,
    ) {
        self.local.authority_pubkey = authority_pubkey;
        self.local.network_marker = network_marker;
    }
}

pub fn capability_summary(bits: Capabilities) -> String {
    let mut parts = Vec::new();
    if bits.contains(Capabilities::ROUTE) {
        parts.push("ROUTE");
    }
    if bits.contains(Capabilities::STORE) {
        parts.push("STORE");
    }
    if bits.contains(Capabilities::BRIDGE) {
        parts.push("BRIDGE");
    }
    if bits.contains(Capabilities::APPLICATION) {
        parts.push("APP");
    }
    if bits.contains(Capabilities::LOW_ENERGY) {
        parts.push("LOW_ENERGY");
    }
    if bits.contains(Capabilities::MOBILE) {
        parts.push("MOBILE");
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join("|")
    }
}
