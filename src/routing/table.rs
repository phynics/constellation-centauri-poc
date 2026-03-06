use heapless::Vec;
use crate::config::{MAX_PEERS, H2H_MAX_PEER_ENTRIES, TICK_HZ};
use crate::crypto::identity::{PubKey, ShortAddr, short_addr_of};
use crate::protocol::dedup::SeenMessages;
use crate::protocol::h2h::{H2hPayload, PeerInfo};
use crate::routing::bloom::BloomFilter;

/// Scaling factor for integer weight computation (avoids floats).
const WEIGHT_SCALE: u64 = 10_000;
/// Minimum weight floor for direct peers so they're always well-represented.
const DIRECT_WEIGHT_FLOOR: u64 = WEIGHT_SCALE / 4;

pub const TRUST_DIRECT: u8 = 3;
pub const TRUST_INDIRECT: u8 = 2;
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
    pub learned_from: ShortAddr,
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

    /// Update a peer from a full H2H exchange. Sets the direct peer as
    /// TRUST_DIRECT and any peers in their peer list as TRUST_INDIRECT.
    ///
    /// `partner_short_addr` is the short address of the peer who sent this
    /// payload — the caller resolves it from the pubkey (if present) or
    /// from the BLE MAC address lookup.
    pub fn update_peer_from_h2h(
        &mut self,
        payload: &H2hPayload,
        partner_short_addr: ShortAddr,
        transport_addr: TransportAddr,
        now_ticks: u64,
    ) {
        let short_addr = partner_short_addr;

        if short_addr == self.self_addr {
            return;
        }

        // Resolve pubkey: use provided value if present, otherwise keep existing
        let resolved_pubkey = match payload.full_pubkey {
            Some(pk) => pk,
            None => {
                self.peers.iter()
                    .find(|p| p.short_addr == short_addr)
                    .map(|p| p.pubkey)
                    .unwrap_or([0u8; 32])
            }
        };

        // Update the direct peer
        if let Some(entry) = self.peers.iter_mut().find(|p| p.short_addr == short_addr) {
            entry.pubkey = resolved_pubkey;
            entry.capabilities = payload.capabilities;
            entry.transport_addr = transport_addr;
            entry.last_seen_ticks = now_ticks;
            entry.hop_count = 0;
            entry.trust = TRUST_DIRECT;
            entry.learned_from = [0u8; 8];
        } else if !self.peers.is_full() {
            let _ = self.peers.push(PeerEntry {
                pubkey: resolved_pubkey,
                short_addr,
                capabilities: payload.capabilities,
                bloom: BloomFilter::new(),
                transport_addr,
                last_seen_ticks: now_ticks,
                hop_count: 0,
                trust: TRUST_DIRECT,
                learned_from: [0u8; 8],
            });
        }

        // Update indirect peers from the peer list
        for i in 0..payload.peer_count as usize {
            if let Some(ref pi) = payload.peers[i] {
                let pi_short_addr = short_addr_of(&pi.pubkey);
                if pi_short_addr == self.self_addr {
                    continue;
                }
                let hop = pi.hop_count.saturating_add(1);

                if let Some(entry) = self.peers.iter_mut().find(|p| p.short_addr == pi_short_addr) {
                    // Only update if our existing info is stale or lower trust
                    if entry.trust <= TRUST_INDIRECT {
                        entry.pubkey = pi.pubkey;
                        entry.capabilities = pi.capabilities;
                        entry.hop_count = hop;
                        entry.last_seen_ticks = now_ticks;
                        entry.trust = TRUST_INDIRECT;
                        entry.learned_from = short_addr;
                    }
                } else if !self.peers.is_full() {
                    let _ = self.peers.push(PeerEntry {
                        pubkey: pi.pubkey,
                        short_addr: pi_short_addr,
                        capabilities: pi.capabilities,
                        bloom: BloomFilter::new(),
                        transport_addr: TransportAddr { addr_type: 0, addr: [0u8; 6] },
                        last_seen_ticks: now_ticks,
                        hop_count: hop,
                        trust: TRUST_INDIRECT,
                        learned_from: short_addr,
                    });
                }
            }
        }

        self.recompute_bloom();
    }

    /// Update a peer from a compact discovery advertisement (short_addr + BLE MAC only).
    /// Returns `true` if this was a newly added peer.
    pub fn update_peer_compact(
        &mut self,
        short_addr: ShortAddr,
        capabilities: u16,
        transport_addr: TransportAddr,
        now_ticks: u64,
    ) -> bool {
        if short_addr == self.self_addr {
            return false;
        }

        if let Some(entry) = self.peers.iter_mut().find(|p| p.short_addr == short_addr) {
            entry.capabilities = capabilities;
            entry.transport_addr = transport_addr;
            entry.last_seen_ticks = now_ticks;
            entry.hop_count = 0;
            entry.trust = TRUST_DIRECT;
            entry.learned_from = [0u8; 8];
            self.recompute_bloom();
            false
        } else if !self.peers.is_full() {
            let _ = self.peers.push(PeerEntry {
                pubkey: [0u8; 32],
                short_addr,
                capabilities,
                bloom: BloomFilter::new(),
                transport_addr,
                last_seen_ticks: now_ticks,
                hop_count: 0,
                trust: TRUST_DIRECT,
                learned_from: [0u8; 8],
            });
            self.recompute_bloom();
            true
        } else {
            false
        }
    }

    /// Build the top N peer entries for an H2H payload destined for `partner_addr`.
    ///
    /// Uses recency-weighted reservoir sampling so fresher peers are more likely
    /// to be selected, but stale peers still have a chance. Indirect peers whose
    /// only source is `partner_addr` are filtered out (the partner already knows
    /// them). Direct peers receive a weight floor to ensure good representation.
    pub fn top_peers_for(
        &self,
        partner_addr: &ShortAddr,
        now_ticks: u64,
        seed: u32,
    ) -> ([Option<PeerInfo>; H2H_MAX_PEER_ENTRIES], u8) {
        const NONE: Option<PeerInfo> = None;
        let mut result = [NONE; H2H_MAX_PEER_ENTRIES];

        // ── Build candidate list with weights ────────────────────────────
        // Weight = WEIGHT_SCALE / ((1 + age_secs) * (1 + hop_count))
        let mut candidates: Vec<(usize, u64), MAX_PEERS> = Vec::new();
        let mut total_weight: u64 = 0;

        for (i, peer) in self.peers.iter().enumerate() {
            // Don't send the partner their own entry — it's implied
            if peer.short_addr == *partner_addr {
                continue;
            }
            // Skip indirect peers learned from this partner
            if peer.trust == TRUST_INDIRECT && peer.learned_from == *partner_addr {
                continue;
            }

            let age_ticks = now_ticks.saturating_sub(peer.last_seen_ticks);
            let age_secs = age_ticks / TICK_HZ;
            let hop = peer.hop_count as u64;
            let denom = (1 + age_secs).saturating_mul(1 + hop);
            let mut w = WEIGHT_SCALE / denom.max(1);

            // Direct peers get a weight floor
            if peer.trust == TRUST_DIRECT && w < DIRECT_WEIGHT_FLOOR {
                w = DIRECT_WEIGHT_FLOOR;
            }

            // Ensure every candidate has at least weight 1
            if w == 0 { w = 1; }

            total_weight = total_weight.saturating_add(w);
            let _ = candidates.push((i, w));
        }

        if candidates.is_empty() {
            return (result, 0);
        }

        // ── Weighted reservoir sampling ───────────────────────────────────
        let mut rng = seed;
        if rng == 0 { rng = 0xDEAD_BEEF; } // xorshift32 must not be zero

        let mut picked = [false; MAX_PEERS];
        let slots = candidates.len().min(H2H_MAX_PEER_ENTRIES);
        let mut count: usize = 0;

        for _ in 0..slots {
            // xorshift32 step
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;

            let threshold = (rng as u64) % total_weight.max(1);
            let mut cumulative: u64 = 0;
            let mut selected: Option<usize> = None;

            for &(idx, w) in candidates.iter() {
                if picked[idx] { continue; }
                cumulative += w;
                if cumulative > threshold {
                    selected = Some(idx);
                    break;
                }
            }

            // Fallback: pick the first unpicked candidate
            let idx = selected.unwrap_or_else(|| {
                candidates.iter()
                    .find(|&&(i, _)| !picked[i])
                    .map(|&(i, _)| i)
                    .unwrap_or(0)
            });

            if picked[idx] { continue; }
            picked[idx] = true;

            // Subtract this peer's weight from total so remaining picks are fair
            if let Some(&(_, w)) = candidates.iter().find(|&&(i, _)| i == idx) {
                total_weight = total_weight.saturating_sub(w);
            }

            let p = &self.peers[idx];
            result[count] = Some(PeerInfo {
                pubkey: p.pubkey,
                capabilities: p.capabilities,
                hop_count: p.hop_count,
            });
            count += 1;
        }

        (result, count as u8)
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
