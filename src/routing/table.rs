use heapless::Vec;
use crate::config::MAX_PEERS;
use crate::crypto::identity::{PubKey, ShortAddr, short_addr_of};
use crate::protocol::dedup::SeenMessages;
use crate::protocol::heartbeat::HeartbeatPayload;
use crate::routing::bloom::BloomFilter;

pub const TRUST_DIRECT: u8 = 3;
pub const TRUST_BLOOM: u8 = 1;
pub const TRUST_EXPIRED: u8 = 0;

pub struct TransportAddr {
    pub addr_type: u8,
    pub addr: [u8; 6],
}

pub struct PeerEntry {
    pub pubkey: PubKey,
    pub short_addr: ShortAddr,
    pub capabilities: u16,
    pub bloom: BloomFilter,
    pub transport_addr: TransportAddr,
    pub last_seen_ticks: u64,
    pub hop_count: u8,
    pub trust: u8,
}

pub struct RoutingTable {
    pub self_addr: ShortAddr,
    pub peers: Vec<PeerEntry, MAX_PEERS>,
    pub local_bloom: BloomFilter,
    pub bloom_generation: u8,
    pub seen: SeenMessages,
}

impl RoutingTable {
    pub fn new(self_addr: ShortAddr) -> Self {
        Self {
            self_addr,
            peers: Vec::new(),
            local_bloom: BloomFilter::new(),
            bloom_generation: 0,
            seen: SeenMessages::new(),
        }
    }

    pub fn update_peer(
        &mut self,
        heartbeat: &HeartbeatPayload,
        transport_addr: TransportAddr,
        now_ticks: u64,
    ) {
        let short_addr = short_addr_of(&heartbeat.full_pubkey);

        // Don't add ourselves
        if short_addr == self.self_addr {
            return;
        }

        // Update existing or insert new
        if let Some(entry) = self.peers.iter_mut().find(|p| p.short_addr == short_addr) {
            entry.capabilities = heartbeat.capabilities;
            entry.bloom.bits = heartbeat.bloom_filter;
            entry.bloom.generation = heartbeat.bloom_generation;
            entry.transport_addr = transport_addr;
            entry.last_seen_ticks = now_ticks;
            entry.hop_count = 0;
            entry.trust = TRUST_DIRECT;
        } else if !self.peers.is_full() {
            let mut bloom = BloomFilter::new();
            bloom.bits = heartbeat.bloom_filter;
            bloom.generation = heartbeat.bloom_generation;

            let _ = self.peers.push(PeerEntry {
                pubkey: heartbeat.full_pubkey,
                short_addr,
                capabilities: heartbeat.capabilities,
                bloom,
                transport_addr,
                last_seen_ticks: now_ticks,
                hop_count: 0,
                trust: TRUST_DIRECT,
            });
        }

        self.recompute_bloom();
    }

    pub fn find_peer(&self, dst: &ShortAddr) -> Option<&PeerEntry> {
        self.peers.iter().find(|p| &p.short_addr == dst)
    }

    /// Find neighbors whose bloom filters claim to know the destination.
    pub fn find_routes(&self, dst: &ShortAddr) -> Vec<usize, 8> {
        let mut indices = Vec::new();
        for (i, peer) in self.peers.iter().enumerate() {
            if peer.bloom.contains(dst) || peer.short_addr == *dst {
                let _ = indices.push(i);
            }
        }
        indices
    }

    pub fn recompute_bloom(&mut self) {
        self.local_bloom.clear();
        self.local_bloom.insert(&self.self_addr);
        for peer in self.peers.iter() {
            self.local_bloom.insert(&peer.short_addr);
        }
        self.bloom_generation = self.bloom_generation.wrapping_add(1);
        self.local_bloom.generation = self.bloom_generation;
    }

    pub fn decay(&mut self, now_ticks: u64, max_age_ticks: u64) {
        let decay_threshold = max_age_ticks;
        let remove_threshold = max_age_ticks * 3;

        self.peers.retain(|peer| {
            let age = now_ticks.saturating_sub(peer.last_seen_ticks);
            age < remove_threshold
        });

        for peer in self.peers.iter_mut() {
            let age = now_ticks.saturating_sub(peer.last_seen_ticks);
            if age >= decay_threshold {
                peer.trust = TRUST_EXPIRED;
            }
        }

        self.recompute_bloom();
    }
}
