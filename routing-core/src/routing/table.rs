use crate::config::{H2H_MAX_PEER_ENTRIES, MAX_PEERS, TICK_HZ};
use crate::crypto::identity::{short_addr_of, PubKey, ShortAddr};
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
            None => self
                .peers
                .iter()
                .find(|p| p.short_addr == short_addr)
                .map(|p| p.pubkey)
                .unwrap_or([0u8; 32]),
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

                if let Some(entry) = self
                    .peers
                    .iter_mut()
                    .find(|p| p.short_addr == pi_short_addr)
                {
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
                        transport_addr: TransportAddr {
                            addr_type: 0,
                            addr: [0u8; 6],
                        },
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
            capabilities: 0x2000 + seed as u16,
            hop_count,
        }
    }

    fn payload(
        full_pubkey: Option<PubKey>,
        capabilities: u16,
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
            capabilities: 0x4444,
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
        let payload = payload(Some(partner_pubkey), 0x9001, &[indirect.clone()]);

        table.update_peer_from_h2h(&payload, partner_addr, transport, now);

        let partner = table.find_peer(&partner_addr).unwrap();
        assert_eq!(partner.pubkey, partner_pubkey);
        assert_eq!(partner.capabilities, 0x9001);
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
            capabilities: 0x7777,
            hop_count: 1,
        };
        let payload = payload(Some(partner_pubkey), 0x1234, &[self_as_indirect]);

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
            0xAAAA,
            &[PeerInfo {
                pubkey: direct_pubkey,
                capabilities: 0xBBBB,
                hop_count: 4,
            }],
        );

        table.update_peer_from_h2h(&payload, partner_addr, TransportAddr::ble(mac(0xC2)), 100);

        let direct = table.find_peer(&direct_addr).unwrap();
        assert_eq!(direct.trust, TRUST_DIRECT);
        assert_eq!(direct.hop_count, 0);
        assert_eq!(direct.transport_addr, original_transport);
        assert_eq!(direct.capabilities, 0x4444);
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
            capabilities: 0x1111,
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
            capabilities: 0x2222,
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
            capabilities: 0x3333,
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
            capabilities: 0x1111,
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
        let inserted = table.update_peer_compact(peer_addr, 0x2222, transport, 250);

        assert!(!inserted);
        let peer = table.find_peer(&peer_addr).unwrap();
        assert_eq!(peer.trust, TRUST_DIRECT);
        assert_eq!(peer.hop_count, 0);
        assert_eq!(peer.capabilities, 0x2222);
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
            capabilities: 0x3333,
            bloom: BloomFilter::new(),
            transport_addr: TransportAddr::ble(mac(0xE5)),
            last_seen_ticks: 10,
            hop_count: 4,
            trust: TRUST_INDIRECT,
            learned_from: short_addr_of(&pubkey(0x73)),
        });

        table.decay(110, 100);
        assert_eq!(table.find_peer(&partner_addr).unwrap().trust, TRUST_EXPIRED);

        let payload = payload(Some(partner_pubkey), 0x4444, &[indirect.clone()]);
        let transport = TransportAddr::ble(mac(0xE6));
        table.update_peer_from_h2h(&payload, partner_addr, transport, 250);

        let partner = table.find_peer(&partner_addr).unwrap();
        assert_eq!(partner.trust, TRUST_DIRECT);
        assert_eq!(partner.hop_count, 0);
        assert_eq!(partner.capabilities, 0x4444);
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
}
