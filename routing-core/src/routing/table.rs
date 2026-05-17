//! Core routing-table state and forwarding selection.
//!
//! Purpose: own peer state, trust levels, dedup state, and forwarding-candidate
//! selection for routed mesh traffic.
//!
//! Design decisions:
//! - Keep the authoritative peer/routing model in shared core so discovery,
//!   H2H sync, and routed forwarding all converge on one table.
//! - Encode trust and candidate selection here instead of splitting routing
//!   behavior across host crates or UI-specific peer caches.

use crate::config::{H2H_MAX_PEER_ENTRIES, MAX_PEERS, TICK_HZ};
use crate::crypto::identity::{short_addr_of, PubKey, ShortAddr};
use crate::node::roles::Capabilities;
use crate::protocol::dedup::SeenMessages;
use crate::protocol::h2h::{H2hPayload, PeerInfo};
use crate::routing::bloom::BloomFilter;
use crate::transport::TransportAddr;
use heapless::Vec;

/// Scaling factor for integer weight computation (avoids floats).
const WEIGHT_SCALE: u64 = 10_000;
/// Minimum weight floor for direct peers so they're always well-represented.
const DIRECT_WEIGHT_FLOOR: u64 = WEIGHT_SCALE / 4;

pub const TRUST_DIRECT: u8 = 3;
pub const TRUST_INDIRECT: u8 = 2;
pub const TRUST_BLOOM: u8 = 1;
pub const TRUST_EXPIRED: u8 = 0;

pub struct PeerEntry {
    pub pubkey: PubKey,
    pub short_addr: ShortAddr,
    pub capabilities: Capabilities,
    pub bloom: BloomFilter,
    pub transport_addr: TransportAddr,
    pub last_seen_ticks: u64,
    pub hop_count: u8,
    pub trust: u8,
    pub learned_from: ShortAddr,
}

impl PeerEntry {
    pub fn direct_from_discovery(
        short_addr: ShortAddr,
        capabilities: Capabilities,
        transport_addr: TransportAddr,
        last_seen_ticks: u64,
    ) -> Self {
        Self {
            pubkey: [0u8; 32],
            short_addr,
            capabilities,
            bloom: BloomFilter::new(),
            transport_addr,
            last_seen_ticks,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0u8; 8],
        }
    }

    pub fn direct_from_h2h(
        pubkey: PubKey,
        short_addr: ShortAddr,
        capabilities: Capabilities,
        transport_addr: TransportAddr,
        last_seen_ticks: u64,
    ) -> Self {
        Self {
            pubkey,
            short_addr,
            capabilities,
            bloom: BloomFilter::new(),
            transport_addr,
            last_seen_ticks,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0u8; 8],
        }
    }

    pub fn indirect_from_peer_info(
        peer: &PeerInfo,
        short_addr: ShortAddr,
        learned_from: ShortAddr,
        last_seen_ticks: u64,
    ) -> Self {
        Self {
            pubkey: peer.pubkey,
            short_addr,
            capabilities: peer.capabilities,
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks,
            hop_count: peer.hop_count.saturating_add(1),
            trust: TRUST_INDIRECT,
            learned_from,
        }
    }

    pub fn refresh_direct_from_discovery(
        &mut self,
        capabilities: Capabilities,
        transport_addr: TransportAddr,
        last_seen_ticks: u64,
    ) {
        self.capabilities = capabilities;
        self.transport_addr = transport_addr;
        self.last_seen_ticks = last_seen_ticks;
        self.hop_count = 0;
        self.trust = TRUST_DIRECT;
        self.learned_from = [0u8; 8];
    }

    pub fn refresh_direct_from_h2h(
        &mut self,
        pubkey: PubKey,
        capabilities: Capabilities,
        transport_addr: TransportAddr,
        last_seen_ticks: u64,
    ) {
        self.pubkey = pubkey;
        self.refresh_direct_from_discovery(capabilities, transport_addr, last_seen_ticks);
    }

    pub fn refresh_indirect_from_peer_info(
        &mut self,
        peer: &PeerInfo,
        learned_from: ShortAddr,
        last_seen_ticks: u64,
    ) {
        self.pubkey = peer.pubkey;
        self.capabilities = peer.capabilities;
        self.hop_count = peer.hop_count.saturating_add(1);
        self.last_seen_ticks = last_seen_ticks;
        self.trust = TRUST_INDIRECT;
        self.learned_from = learned_from;
    }

    pub fn as_peer_info(&self) -> PeerInfo {
        PeerInfo {
            pubkey: self.pubkey,
            capabilities: self.capabilities,
            hop_count: self.hop_count,
        }
    }
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
            None => self
                .peers
                .iter()
                .find(|p| p.short_addr == short_addr)
                .map(|p| p.pubkey)
                .unwrap_or([0u8; 32]),
        };

        // Update the direct peer
        if let Some(entry) = self.peers.iter_mut().find(|p| p.short_addr == short_addr) {
            entry.refresh_direct_from_h2h(resolved_pubkey, payload.capabilities, transport_addr, now_ticks);
        } else if !self.peers.is_full() {
            let _ = self.peers.push(PeerEntry::direct_from_h2h(
                resolved_pubkey,
                short_addr,
                payload.capabilities,
                transport_addr,
                now_ticks,
            ));
        }

        // Update indirect peers from the peer list
        for i in 0..payload.peer_count as usize {
                if let Some(ref pi) = payload.peers[i] {
                    let pi_short_addr = short_addr_of(&pi.pubkey);
                    if pi_short_addr == self.self_addr {
                        continue;
                    }

                    if let Some(entry) = self
                        .peers
                    .iter_mut()
                    .find(|p| p.short_addr == pi_short_addr)
                {
                    // Only update if our existing info is stale or lower trust
                    if entry.trust <= TRUST_INDIRECT {
                        entry.refresh_indirect_from_peer_info(pi, short_addr, now_ticks);
                    }
                } else if !self.peers.is_full() {
                    let _ = self.peers.push(PeerEntry::indirect_from_peer_info(
                        pi,
                        pi_short_addr,
                        short_addr,
                        now_ticks,
                    ));
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
        capabilities: Capabilities,
        transport_addr: TransportAddr,
        now_ticks: u64,
    ) -> bool {
        if short_addr == self.self_addr {
            return false;
        }

        if let Some(entry) = self.peers.iter_mut().find(|p| p.short_addr == short_addr) {
            entry.refresh_direct_from_discovery(capabilities, transport_addr, now_ticks);
            self.recompute_bloom();
            false
        } else if !self.peers.is_full() {
            let _ = self.peers.push(PeerEntry::direct_from_discovery(
                short_addr,
                capabilities,
                transport_addr,
                now_ticks,
            ));
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
            if w == 0 {
                w = 1;
            }

            total_weight = total_weight.saturating_add(w);
            let _ = candidates.push((i, w));
        }

        if candidates.is_empty() {
            return (result, 0);
        }

        // ── Weighted reservoir sampling ───────────────────────────────────
        let mut rng = seed;
        if rng == 0 {
            rng = 0xDEAD_BEEF; // xorshift32 must not be zero
        }

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
                if picked[idx] {
                    continue;
                }
                cumulative += w;
                if cumulative > threshold {
                    selected = Some(idx);
                    break;
                }
            }

            // Fallback: pick the first unpicked candidate
            let idx = selected.unwrap_or_else(|| {
                candidates
                    .iter()
                    .find(|&&(i, _)| !picked[i])
                    .map(|&(i, _)| i)
                    .unwrap_or(0)
            });

            if picked[idx] {
                continue;
            }
            picked[idx] = true;

            // Subtract this peer's weight from total so remaining picks are fair
            if let Some(&(_, w)) = candidates.iter().find(|&&(i, _)| i == idx) {
                total_weight = total_weight.saturating_sub(w);
            }

            let p = &self.peers[idx];
            result[count] = Some(p.as_peer_info());
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

    fn is_usable_transport_peer(peer: &PeerEntry) -> bool {
        peer.trust > TRUST_EXPIRED && !peer.transport_addr.is_empty()
    }

    fn usable_peer_by_short_addr(&self, short_addr: &ShortAddr) -> Option<&PeerEntry> {
        self.peers
            .iter()
            .find(|peer| peer.short_addr == *short_addr && Self::is_usable_transport_peer(peer))
    }

    /// Return forwarding candidates for a destination using current routing knowledge.
    ///
    /// The direct destination is preferred when known and still has a usable
    /// transport address. Otherwise, candidates are derived from neighbors whose
    /// direct entry or bloom filter claims they know the destination.
    pub fn forwarding_candidates(&self, dst: &ShortAddr) -> Vec<(ShortAddr, TransportAddr), 8> {
        let mut candidates = Vec::new();

        if let Some(peer) = self.find_peer(dst) {
            if Self::is_usable_transport_peer(peer) {
                let _ = candidates.push((peer.short_addr, peer.transport_addr));
                return candidates;
            }

            if peer.trust == TRUST_INDIRECT {
                if let Some(next_hop) = self.usable_peer_by_short_addr(&peer.learned_from) {
                    let _ = candidates.push((next_hop.short_addr, next_hop.transport_addr));
                    return candidates;
                }
            }
        }

        for idx in self.find_routes(dst).iter().copied() {
            if let Some(peer) = self.peers.get(idx) {
                if !Self::is_usable_transport_peer(peer) {
                    continue;
                }
                let candidate = (peer.short_addr, peer.transport_addr);
                if !candidates.iter().any(|existing| existing.0 == candidate.0) {
                    let _ = candidates.push(candidate);
                }
            }
        }

        candidates
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::h2h::H2hPayload;

    fn pubkey(seed: u8) -> PubKey {
        [seed; 32]
    }

    fn mac(seed: u8) -> [u8; 6] {
        [seed; 6]
    }

    fn indirect_peer(seed: u8, hop_count: u8) -> PeerInfo {
        PeerInfo {
            pubkey: pubkey(seed),
            capabilities: Capabilities::new(0x2000 + seed as u16),
            hop_count,
        }
    }

    fn payload(
        full_pubkey: Option<PubKey>,
        capabilities: Capabilities,
        peer_infos: &[PeerInfo],
    ) -> H2hPayload {
        const NONE: Option<PeerInfo> = None;
        let mut peers = [NONE; H2H_MAX_PEER_ENTRIES];
        for (i, peer) in peer_infos.iter().enumerate() {
            peers[i] = Some(peer.clone());
        }

        H2hPayload {
            full_pubkey,
            capabilities,
            uptime_secs: 99,
            peers,
            peer_count: peer_infos.len() as u8,
        }
    }

    fn direct_peer_entry(
        pubkey: PubKey,
        transport_addr: TransportAddr,
        last_seen_ticks: u64,
    ) -> PeerEntry {
        PeerEntry {
            short_addr: short_addr_of(&pubkey),
            pubkey,
            capabilities: Capabilities::new(0x4444),
            bloom: BloomFilter::new(),
            transport_addr,
            last_seen_ticks,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0u8; 8],
        }
    }

    #[test]
    fn update_peer_from_h2h_marks_direct_and_indirect_peers() {
        let self_pubkey = pubkey(0x01);
        let self_addr = short_addr_of(&self_pubkey);
        let partner_pubkey = pubkey(0x02);
        let partner_addr = short_addr_of(&partner_pubkey);
        let transport = TransportAddr::ble(mac(0xA0));
        let now = 12345;

        let mut table = RoutingTable::new(self_addr);
        let indirect = indirect_peer(0x03, 2);
        let payload = payload(
            Some(partner_pubkey),
            Capabilities::new(0x9001),
            &[indirect.clone()],
        );

        table.update_peer_from_h2h(&payload, partner_addr, transport, now);

        let partner = table.find_peer(&partner_addr).unwrap();
        assert_eq!(partner.pubkey, partner_pubkey);
        assert_eq!(partner.capabilities, Capabilities::new(0x9001));
        assert_eq!(partner.transport_addr, transport);
        assert_eq!(partner.last_seen_ticks, now);
        assert_eq!(partner.hop_count, 0);
        assert_eq!(partner.trust, TRUST_DIRECT);
        assert_eq!(partner.learned_from, [0u8; 8]);

        let indirect_addr = short_addr_of(&indirect.pubkey);
        let learned = table.find_peer(&indirect_addr).unwrap();
        assert_eq!(learned.pubkey, indirect.pubkey);
        assert_eq!(learned.capabilities, indirect.capabilities);
        assert_eq!(learned.hop_count, indirect.hop_count + 1);
        assert_eq!(learned.trust, TRUST_INDIRECT);
        assert_eq!(learned.learned_from, partner_addr);
    }

    #[test]
    fn update_peer_from_h2h_ignores_self_in_peer_list() {
        let self_pubkey = pubkey(0x10);
        let self_addr = short_addr_of(&self_pubkey);
        let partner_pubkey = pubkey(0x11);
        let partner_addr = short_addr_of(&partner_pubkey);
        let transport = TransportAddr::ble(mac(0xB0));

        let mut table = RoutingTable::new(self_addr);
        let self_as_indirect = PeerInfo {
            pubkey: self_pubkey,
            capabilities: Capabilities::new(0x7777),
            hop_count: 1,
        };
        let payload = payload(
            Some(partner_pubkey),
            Capabilities::new(0x1234),
            &[self_as_indirect],
        );

        table.update_peer_from_h2h(&payload, partner_addr, transport, 50);

        assert_eq!(table.peers.len(), 1);
        assert!(table.find_peer(&self_addr).is_none());
        assert!(table.find_peer(&partner_addr).is_some());
    }

    #[test]
    fn indirect_update_does_not_downgrade_existing_direct_peer() {
        let self_addr = short_addr_of(&pubkey(0x20));
        let direct_pubkey = pubkey(0x21);
        let direct_addr = short_addr_of(&direct_pubkey);
        let original_transport = TransportAddr::ble(mac(0xC1));
        let partner_pubkey = pubkey(0x22);
        let partner_addr = short_addr_of(&partner_pubkey);

        let mut table = RoutingTable::new(self_addr);
        let _ = table
            .peers
            .push(direct_peer_entry(direct_pubkey, original_transport, 10));

        let payload = payload(
            Some(partner_pubkey),
            Capabilities::new(0xAAAA),
            &[PeerInfo {
                pubkey: direct_pubkey,
                capabilities: Capabilities::new(0xBBBB),
                hop_count: 4,
            }],
        );

        table.update_peer_from_h2h(&payload, partner_addr, TransportAddr::ble(mac(0xC2)), 100);

        let direct = table.find_peer(&direct_addr).unwrap();
        assert_eq!(direct.trust, TRUST_DIRECT);
        assert_eq!(direct.hop_count, 0);
        assert_eq!(direct.transport_addr, original_transport);
        assert_eq!(direct.capabilities, Capabilities::new(0x4444));
        assert_eq!(direct.last_seen_ticks, 10);
    }

    #[test]
    fn top_peers_for_excludes_partner_and_partner_learned_indirects() {
        let self_addr = short_addr_of(&pubkey(0x30));
        let partner_pubkey = pubkey(0x31);
        let partner_addr = short_addr_of(&partner_pubkey);
        let direct_other_pubkey = pubkey(0x32);
        let direct_other_addr = short_addr_of(&direct_other_pubkey);
        let indirect_from_partner = pubkey(0x33);
        let indirect_from_partner_addr = short_addr_of(&indirect_from_partner);

        let mut table = RoutingTable::new(self_addr);
        let _ = table.peers.push(PeerEntry {
            short_addr: partner_addr,
            pubkey: partner_pubkey,
            capabilities: Capabilities::new(0x1111),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::ble(mac(0xD1)),
            last_seen_ticks: 100,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0u8; 8],
        });
        let _ = table.peers.push(PeerEntry {
            short_addr: direct_other_addr,
            pubkey: direct_other_pubkey,
            capabilities: Capabilities::new(0x2222),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::ble(mac(0xD2)),
            last_seen_ticks: 100,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0u8; 8],
        });
        let _ = table.peers.push(PeerEntry {
            short_addr: indirect_from_partner_addr,
            pubkey: indirect_from_partner,
            capabilities: Capabilities::new(0x3333),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::ble([0u8; 6]),
            last_seen_ticks: 100,
            hop_count: 2,
            trust: TRUST_INDIRECT,
            learned_from: partner_addr,
        });

        let (selected, count) = table.top_peers_for(&partner_addr, 100, 0x1234_5678);

        assert_eq!(count, 1);
        let selected_peer = selected[0].as_ref().unwrap();
        assert_eq!(selected_peer.pubkey, direct_other_pubkey);
        assert!(selected[1..].iter().all(|entry| entry.is_none()));
    }

    #[test]
    fn decay_marks_stale_peers_expired_without_removing_them() {
        let self_addr = short_addr_of(&pubkey(0x40));
        let stale_pubkey = pubkey(0x41);
        let stale_addr = short_addr_of(&stale_pubkey);
        let mut table = RoutingTable::new(self_addr);

        let _ = table.peers.push(direct_peer_entry(
            stale_pubkey,
            TransportAddr::ble(mac(0xE1)),
            10,
        ));

        table.decay(110, 100);

        let peer = table.find_peer(&stale_addr).unwrap();
        assert_eq!(peer.trust, TRUST_EXPIRED);
        assert_eq!(table.peers.len(), 1);
    }

    #[test]
    fn decay_removes_very_old_peers() {
        let self_addr = short_addr_of(&pubkey(0x50));
        let old_pubkey = pubkey(0x51);
        let old_addr = short_addr_of(&old_pubkey);
        let mut table = RoutingTable::new(self_addr);

        let _ = table.peers.push(direct_peer_entry(
            old_pubkey,
            TransportAddr::ble(mac(0xE2)),
            10,
        ));

        table.decay(310, 100);

        assert!(table.find_peer(&old_addr).is_none());
        assert!(table.peers.is_empty());
    }

    #[test]
    fn compact_update_recovers_expired_peer_to_direct() {
        let self_addr = short_addr_of(&pubkey(0x60));
        let peer_pubkey = pubkey(0x61);
        let peer_addr = short_addr_of(&peer_pubkey);
        let mut table = RoutingTable::new(self_addr);

        let _ = table.peers.push(PeerEntry {
            short_addr: peer_addr,
            pubkey: peer_pubkey,
            capabilities: Capabilities::new(0x1111),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::ble(mac(0xE3)),
            last_seen_ticks: 10,
            hop_count: 2,
            trust: TRUST_INDIRECT,
            learned_from: short_addr_of(&pubkey(0x62)),
        });

        table.decay(110, 100);
        assert_eq!(table.find_peer(&peer_addr).unwrap().trust, TRUST_EXPIRED);

        let transport = TransportAddr::ble(mac(0xE4));
        let inserted =
            table.update_peer_compact(peer_addr, Capabilities::new(0x2222), transport, 250);

        assert!(!inserted);
        let peer = table.find_peer(&peer_addr).unwrap();
        assert_eq!(peer.trust, TRUST_DIRECT);
        assert_eq!(peer.hop_count, 0);
        assert_eq!(peer.capabilities, Capabilities::new(0x2222));
        assert_eq!(peer.transport_addr, transport);
        assert_eq!(peer.last_seen_ticks, 250);
        assert_eq!(peer.learned_from, [0u8; 8]);
    }

    #[test]
    fn h2h_update_recovers_expired_peer_to_direct_and_refreshes_indirects() {
        let self_addr = short_addr_of(&pubkey(0x70));
        let partner_pubkey = pubkey(0x71);
        let partner_addr = short_addr_of(&partner_pubkey);
        let indirect = indirect_peer(0x72, 1);
        let indirect_addr = short_addr_of(&indirect.pubkey);
        let mut table = RoutingTable::new(self_addr);

        let _ = table.peers.push(PeerEntry {
            short_addr: partner_addr,
            pubkey: partner_pubkey,
            capabilities: Capabilities::new(0x3333),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::ble(mac(0xE5)),
            last_seen_ticks: 10,
            hop_count: 4,
            trust: TRUST_INDIRECT,
            learned_from: short_addr_of(&pubkey(0x73)),
        });

        table.decay(110, 100);
        assert_eq!(table.find_peer(&partner_addr).unwrap().trust, TRUST_EXPIRED);

        let payload = payload(
            Some(partner_pubkey),
            Capabilities::new(0x4444),
            &[indirect.clone()],
        );
        let transport = TransportAddr::ble(mac(0xE6));
        table.update_peer_from_h2h(&payload, partner_addr, transport, 250);

        let partner = table.find_peer(&partner_addr).unwrap();
        assert_eq!(partner.trust, TRUST_DIRECT);
        assert_eq!(partner.hop_count, 0);
        assert_eq!(partner.capabilities, Capabilities::new(0x4444));
        assert_eq!(partner.transport_addr, transport);
        assert_eq!(partner.last_seen_ticks, 250);
        assert_eq!(partner.learned_from, [0u8; 8]);

        let indirect_peer = table.find_peer(&indirect_addr).unwrap();
        assert_eq!(indirect_peer.trust, TRUST_INDIRECT);
        assert_eq!(indirect_peer.hop_count, indirect.hop_count + 1);
        assert_eq!(indirect_peer.learned_from, partner_addr);
        assert_eq!(indirect_peer.last_seen_ticks, 250);
    }

    #[test]
    fn decay_recomputes_bloom_after_removal() {
        let self_addr = short_addr_of(&pubkey(0x80));
        let old_pubkey = pubkey(0x81);
        let old_addr = short_addr_of(&old_pubkey);
        let mut table = RoutingTable::new(self_addr);

        let _ = table.peers.push(direct_peer_entry(
            old_pubkey,
            TransportAddr::ble(mac(0xE7)),
            10,
        ));
        table.recompute_bloom();
        assert!(table.local_bloom.contains(&old_addr));
        assert_eq!(table.find_routes(&old_addr).len(), 1);

        table.decay(310, 100);

        assert!(!table.local_bloom.contains(&old_addr));
        assert!(table.find_routes(&old_addr).is_empty());
    }

    #[test]
    fn forwarding_candidates_prefers_direct_destination() {
        let self_addr = short_addr_of(&pubkey(0x82));
        let dst_pubkey = pubkey(0x83);
        let dst_addr = short_addr_of(&dst_pubkey);
        let dst_transport = TransportAddr::ble(mac(0xE8));
        let mut table = RoutingTable::new(self_addr);

        let _ = table
            .peers
            .push(direct_peer_entry(dst_pubkey, dst_transport, 10));

        let candidates = table.forwarding_candidates(&dst_addr);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, dst_addr);
        assert_eq!(candidates[0].1, dst_transport);
    }

    #[test]
    fn forwarding_candidates_uses_bloom_routes_when_no_direct_destination_exists() {
        let self_addr = short_addr_of(&pubkey(0x84));
        let via_pubkey = pubkey(0x85);
        let via_addr = short_addr_of(&via_pubkey);
        let dst_addr = short_addr_of(&pubkey(0x86));
        let mut table = RoutingTable::new(self_addr);

        let mut via = direct_peer_entry(via_pubkey, TransportAddr::ble(mac(0xE9)), 10);
        via.bloom.insert(&dst_addr);
        let _ = table.peers.push(via);

        let candidates = table.forwarding_candidates(&dst_addr);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, via_addr);
    }

    #[test]
    fn forwarding_candidates_resolves_indirect_destination_via_learned_from() {
        let self_addr = short_addr_of(&pubkey(0x90));
        let learned_from_pubkey = pubkey(0x91);
        let learned_from_addr = short_addr_of(&learned_from_pubkey);
        let indirect_pubkey = pubkey(0x92);
        let indirect_addr = short_addr_of(&indirect_pubkey);
        let transport = TransportAddr::ble(mac(0xF0));
        let mut table = RoutingTable::new(self_addr);

        let _ = table
            .peers
            .push(direct_peer_entry(learned_from_pubkey, transport, 10));
        let _ = table.peers.push(PeerEntry {
            short_addr: indirect_addr,
            pubkey: indirect_pubkey,
            capabilities: Capabilities::new(0x5555),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 20,
            hop_count: 2,
            trust: TRUST_INDIRECT,
            learned_from: learned_from_addr,
        });

        let candidates = table.forwarding_candidates(&indirect_addr);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, learned_from_addr);
        assert_eq!(candidates[0].1, transport);
    }

    #[test]
    fn forwarding_candidates_returns_empty_when_indirect_learned_from_is_unusable() {
        let self_addr = short_addr_of(&pubkey(0x93));
        let learned_from_pubkey = pubkey(0x94);
        let learned_from_addr = short_addr_of(&learned_from_pubkey);
        let indirect_pubkey = pubkey(0x95);
        let indirect_addr = short_addr_of(&indirect_pubkey);
        let mut table = RoutingTable::new(self_addr);

        let _ = table.peers.push(PeerEntry {
            short_addr: learned_from_addr,
            pubkey: learned_from_pubkey,
            capabilities: Capabilities::new(0x1111),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 10,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0u8; 8],
        });
        let _ = table.peers.push(PeerEntry {
            short_addr: indirect_addr,
            pubkey: indirect_pubkey,
            capabilities: Capabilities::new(0x2222),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 20,
            hop_count: 3,
            trust: TRUST_INDIRECT,
            learned_from: learned_from_addr,
        });

        let candidates = table.forwarding_candidates(&indirect_addr);

        assert!(candidates.is_empty());
    }

    #[test]
    fn forwarding_candidates_falls_back_to_bloom_when_learned_from_is_unusable() {
        let self_addr = short_addr_of(&pubkey(0x96));
        let learned_from_pubkey = pubkey(0x97);
        let learned_from_addr = short_addr_of(&learned_from_pubkey);
        let bloom_via_pubkey = pubkey(0x98);
        let bloom_via_addr = short_addr_of(&bloom_via_pubkey);
        let indirect_pubkey = pubkey(0x99);
        let indirect_addr = short_addr_of(&indirect_pubkey);
        let mut table = RoutingTable::new(self_addr);

        let _ = table.peers.push(PeerEntry {
            short_addr: learned_from_addr,
            pubkey: learned_from_pubkey,
            capabilities: Capabilities::new(0x1111),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 10,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0u8; 8],
        });
        let mut bloom_via = direct_peer_entry(bloom_via_pubkey, TransportAddr::ble(mac(0xF1)), 15);
        bloom_via.bloom.insert(&indirect_addr);
        let _ = table.peers.push(bloom_via);
        let _ = table.peers.push(PeerEntry {
            short_addr: indirect_addr,
            pubkey: indirect_pubkey,
            capabilities: Capabilities::new(0x2222),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 20,
            hop_count: 3,
            trust: TRUST_INDIRECT,
            learned_from: learned_from_addr,
        });

        let candidates = table.forwarding_candidates(&indirect_addr);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, bloom_via_addr);
    }

    #[test]
    fn forwarding_candidates_resolve_multiple_indirect_destinations_via_their_own_partners() {
        let self_addr = short_addr_of(&pubkey(0xA0));
        let partner_a_pubkey = pubkey(0xA1);
        let partner_b_pubkey = pubkey(0xA2);
        let partner_a_addr = short_addr_of(&partner_a_pubkey);
        let partner_b_addr = short_addr_of(&partner_b_pubkey);
        let indirect_a_pubkey = pubkey(0xA3);
        let indirect_b_pubkey = pubkey(0xA4);
        let indirect_a_addr = short_addr_of(&indirect_a_pubkey);
        let indirect_b_addr = short_addr_of(&indirect_b_pubkey);
        let mut table = RoutingTable::new(self_addr);

        let _ = table.peers.push(direct_peer_entry(
            partner_a_pubkey,
            TransportAddr::ble(mac(0xF2)),
            10,
        ));
        let _ = table.peers.push(direct_peer_entry(
            partner_b_pubkey,
            TransportAddr::ble(mac(0xF3)),
            10,
        ));
        let _ = table.peers.push(PeerEntry {
            short_addr: indirect_a_addr,
            pubkey: indirect_a_pubkey,
            capabilities: Capabilities::new(0x3333),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 20,
            hop_count: 2,
            trust: TRUST_INDIRECT,
            learned_from: partner_a_addr,
        });
        let _ = table.peers.push(PeerEntry {
            short_addr: indirect_b_addr,
            pubkey: indirect_b_pubkey,
            capabilities: Capabilities::new(0x4444),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 20,
            hop_count: 2,
            trust: TRUST_INDIRECT,
            learned_from: partner_b_addr,
        });

        let candidates_a = table.forwarding_candidates(&indirect_a_addr);
        let candidates_b = table.forwarding_candidates(&indirect_b_addr);

        assert_eq!(candidates_a.len(), 1);
        assert_eq!(candidates_a[0].0, partner_a_addr);
        assert_eq!(candidates_b.len(), 1);
        assert_eq!(candidates_b[0].0, partner_b_addr);
    }

    #[test]
    fn multi_hop_partitioned_route_resolves_via_bridge() {
        // Topology: A --- bridge --- C
        // A knows bridge directly, C indirectly via bridge.
        // A should route to C via bridge.
        let a_addr = short_addr_of(&pubkey(0xB0));
        let bridge_pubkey = pubkey(0xB1);
        let bridge_addr = short_addr_of(&bridge_pubkey);
        let bridge_transport = TransportAddr::ble(mac(0xF4));
        let c_pubkey = pubkey(0xB2);
        let c_addr = short_addr_of(&c_pubkey);

        let mut table = RoutingTable::new(a_addr);

        // A's direct peer: bridge
        let _ = table
            .peers
            .push(direct_peer_entry(bridge_pubkey, bridge_transport, 10));

        // A's indirect peer: C, learned from bridge
        let _ = table.peers.push(PeerEntry {
            short_addr: c_addr,
            pubkey: c_pubkey,
            capabilities: Capabilities::new(0x7777),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 20,
            hop_count: 2,
            trust: TRUST_INDIRECT,
            learned_from: bridge_addr,
        });

        let candidates = table.forwarding_candidates(&c_addr);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, bridge_addr);
        assert_eq!(candidates[0].1, bridge_transport);
    }

    #[test]
    fn multi_hop_two_hop_route_via_h2h_exchange() {
        // Simulate a full H2H chain: A <-> B <-> C, A not linked to C.
        // A does H2H with B, learns C as indirect from B.
        // A should route to C via B.
        let a_pubkey = pubkey(0xC0);
        let a_addr = short_addr_of(&a_pubkey);
        let b_pubkey = pubkey(0xC1);
        let b_addr = short_addr_of(&b_pubkey);
        let b_transport = TransportAddr::ble(mac(0xF5));
        let c_pubkey = pubkey(0xC2);
        let c_addr = short_addr_of(&c_pubkey);

        let mut table = RoutingTable::new(a_addr);

        // H2H exchange: B tells A about C
        let payload = H2hPayload {
            full_pubkey: Some(b_pubkey),
            capabilities: Capabilities::new(0x8800),
            uptime_secs: 100,
            peers: {
                const NONE: Option<PeerInfo> = None;
                let mut p = [NONE; H2H_MAX_PEER_ENTRIES];
                p[0] = Some(PeerInfo {
                    pubkey: c_pubkey,
                    capabilities: Capabilities::new(0x9900),
                    hop_count: 0,
                });
                p
            },
            peer_count: 1,
        };

        table.update_peer_from_h2h(&payload, b_addr, b_transport, 50);

        // Verify A learned C as indirect from B
        let c_entry = table.find_peer(&c_addr).unwrap();
        assert_eq!(c_entry.trust, TRUST_INDIRECT);
        assert_eq!(c_entry.learned_from, b_addr);

        // Verify A can route to C via B
        let candidates = table.forwarding_candidates(&c_addr);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, b_addr);
        assert_eq!(candidates[0].1, b_transport);
    }

    #[test]
    fn multi_hop_three_hop_chain_resolves_step_by_step() {
        // Chain: A <-> B <-> C <-> D
        // A knows B directly, C indirectly via B, D indirectly via B.
        // A should route to D via B (B is the learned_from for both C and D).
        let a_addr = short_addr_of(&pubkey(0xD0));
        let b_pubkey = pubkey(0xD1);
        let b_addr = short_addr_of(&b_pubkey);
        let b_transport = TransportAddr::ble(mac(0xF6));
        let c_pubkey = pubkey(0xD2);
        let c_addr = short_addr_of(&c_pubkey);
        let d_pubkey = pubkey(0xD3);
        let d_addr = short_addr_of(&d_pubkey);

        let mut table = RoutingTable::new(a_addr);

        // Direct: B
        let _ = table
            .peers
            .push(direct_peer_entry(b_pubkey, b_transport, 10));

        // Indirect: C learned from B, hop_count=2
        let _ = table.peers.push(PeerEntry {
            short_addr: c_addr,
            pubkey: c_pubkey,
            capabilities: Capabilities::new(0xAA00),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 20,
            hop_count: 2,
            trust: TRUST_INDIRECT,
            learned_from: b_addr,
        });

        // Indirect: D learned from B, hop_count=3
        let _ = table.peers.push(PeerEntry {
            short_addr: d_addr,
            pubkey: d_pubkey,
            capabilities: Capabilities::new(0xBB00),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 20,
            hop_count: 3,
            trust: TRUST_INDIRECT,
            learned_from: b_addr,
        });

        // A routes to C via B
        let candidates_c = table.forwarding_candidates(&c_addr);
        assert_eq!(candidates_c.len(), 1);
        assert_eq!(candidates_c[0].0, b_addr);

        // A routes to D via B
        let candidates_d = table.forwarding_candidates(&d_addr);
        assert_eq!(candidates_d.len(), 1);
        assert_eq!(candidates_d[0].0, b_addr);
    }

    #[test]
    fn multi_hop_bridge_learns_both_partitions_and_routes_cross() {
        // Partitioned: A <-> bridge <-> C
        // Bridge does H2H with A (learns A directly) and H2H with C (learns C directly).
        // Bridge should route to A directly and to C directly.
        // This tests the bridge's own routing table convergence.
        let bridge_addr = short_addr_of(&pubkey(0xE0));
        let a_pubkey = pubkey(0xE1);
        let a_addr = short_addr_of(&a_pubkey);
        let a_transport = TransportAddr::ble(mac(0xF7));
        let c_pubkey = pubkey(0xE2);
        let c_addr = short_addr_of(&c_pubkey);
        let c_transport = TransportAddr::ble(mac(0xF8));

        let mut table = RoutingTable::new(bridge_addr);

        // Bridge H2H with A
        let payload_a = H2hPayload {
            full_pubkey: Some(a_pubkey),
            capabilities: Capabilities::new(0xCC00),
            uptime_secs: 50,
            peers: {
                const NONE: Option<PeerInfo> = None;
                [NONE; H2H_MAX_PEER_ENTRIES]
            },
            peer_count: 0,
        };
        table.update_peer_from_h2h(&payload_a, a_addr, a_transport, 100);

        // Bridge H2H with C
        let payload_c = H2hPayload {
            full_pubkey: Some(c_pubkey),
            capabilities: Capabilities::new(0xDD00),
            uptime_secs: 50,
            peers: {
                const NONE: Option<PeerInfo> = None;
                [NONE; H2H_MAX_PEER_ENTRIES]
            },
            peer_count: 0,
        };
        table.update_peer_from_h2h(&payload_c, c_addr, c_transport, 100);

        // Bridge routes to A directly
        let candidates_a = table.forwarding_candidates(&a_addr);
        assert_eq!(candidates_a.len(), 1);
        assert_eq!(candidates_a[0].0, a_addr);
        assert_eq!(candidates_a[0].1, a_transport);

        // Bridge routes to C directly
        let candidates_c = table.forwarding_candidates(&c_addr);
        assert_eq!(candidates_c.len(), 1);
        assert_eq!(candidates_c[0].0, c_addr);
        assert_eq!(candidates_c[0].1, c_transport);
    }

    #[test]
    fn multi_hop_expired_bridge_prevents_indirect_routing() {
        // A <-> bridge <-> C, but bridge has expired.
        // A should not be able to route to C via bridge.
        let a_addr = short_addr_of(&pubkey(0xF0));
        let bridge_pubkey = pubkey(0xF1);
        let bridge_addr = short_addr_of(&bridge_pubkey);
        let bridge_transport = TransportAddr::ble(mac(0xF9));
        let c_pubkey = pubkey(0xF2);
        let c_addr = short_addr_of(&c_pubkey);

        let mut table = RoutingTable::new(a_addr);

        let _ = table
            .peers
            .push(direct_peer_entry(bridge_pubkey, bridge_transport, 10));

        let _ = table.peers.push(PeerEntry {
            short_addr: c_addr,
            pubkey: c_pubkey,
            capabilities: Capabilities::new(0xEE00),
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::empty(),
            last_seen_ticks: 20,
            hop_count: 2,
            trust: TRUST_INDIRECT,
            learned_from: bridge_addr,
        });

        // Expire the bridge
        table.decay(200, 100);
        let bridge_entry = table.find_peer(&bridge_addr).unwrap();
        assert_eq!(bridge_entry.trust, TRUST_EXPIRED);

        // A can no longer route to C — learned_from is expired
        let candidates = table.forwarding_candidates(&c_addr);
        assert!(candidates.is_empty());
    }
}
