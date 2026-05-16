//! H2H (Heart2Heart) — direct peer heartbeat exchange protocol.
//!
//! Two nodes connect via BLE L2CAP and exchange heartbeat payloads that include
//! their known peer lists. This replaces broadcast-only heartbeats.
//!
//! ## Pair scheduling
//!
//! For any pair (A, B), a deterministic `pair_hash` is computed from the
//! canonical ordering of their ShortAddrs. This yields:
//!
//! - **Initiator**: the node with the lexicographically smaller ShortAddr.
//! - **Slot offset**: `u16_from(pair_hash[0..2]) % cycle_secs` — the second
//!   within the 60 s cycle at which the initiator should connect.
//!
//! Both nodes compute the same values with no coordination.

use core::convert::TryInto;

use heapless::Vec;
use sha2::{Digest, Sha256};

use crate::config::{H2H_CYCLE_SECS, H2H_MAX_PEER_ENTRIES};
use crate::crypto::identity::{PubKey, ShortAddr};
use crate::protocol::packet::PacketError;

/// Current H2H protocol version. Bumped on breaking wire-format changes.
pub const H2H_VERSION: u8 = 0x02;
/// Maximum metadata/body bytes transferred in a single delivery frame.
///
/// The simulator currently uses H2H delivery frames for delayed-delivery
/// control/data exchange rather than for arbitrary large application payloads.
/// Keeping the frame body bounded preserves the fixed-buffer/no-std model and
/// is sufficient for the current trace-driven simulator behavior.
pub const H2H_DELIVERY_BODY_MAX: usize = 96;
/// Upper bound on the number of per-frame delivery acknowledgements.
pub const H2H_ACK_IDS_MAX: usize = 8;

// ── Pair scheduling ──────────────────────────────────────────────────────────

/// Returns `true` if `our_addr < peer_addr` (lexicographic), meaning we
/// are the initiator for this pair.
pub fn is_initiator(our_addr: &ShortAddr, peer_addr: &ShortAddr) -> bool {
    our_addr < peer_addr
}

/// Deterministic hash of a pair of addresses (canonical order).
fn pair_hash(a: &ShortAddr, b: &ShortAddr) -> [u8; 32] {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut hasher = Sha256::new();
    hasher.update(lo);
    hasher.update(hi);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute the slot offset (in seconds) within the H2H cycle for a pair.
pub fn slot_offset(our_addr: &ShortAddr, peer_addr: &ShortAddr) -> u64 {
    let h = pair_hash(our_addr, peer_addr);
    let raw = u16::from_le_bytes([h[0], h[1]]) as u64;
    raw % H2H_CYCLE_SECS
}

// ── H2H payload ──────────────────────────────────────────────────────────────

/// Information about a single known peer, transmitted in the H2H exchange.
#[derive(Clone)]
pub struct PeerInfo {
    pub pubkey: PubKey,
    pub capabilities: u16,
    pub hop_count: u8,
}

const PEER_INFO_SIZE: usize = 32 + 2 + 1; // 35

/// H2H exchange payload — sent and received over L2CAP.
pub struct H2hPayload {
    /// If `Some`, the sender's full 32-byte public key. Omitted when the
    /// partner already has it (saves 32 bytes per exchange).
    pub full_pubkey: Option<PubKey>,
    pub capabilities: u16,
    pub uptime_secs: u32,
    pub peers: [Option<PeerInfo>; H2H_MAX_PEER_ENTRIES],
    pub peer_count: u8,
}

/// Additional typed frames exchanged after the initial H2H sync request /
/// response. These frames intentionally extend H2H rather than introducing a
/// parallel low-power-only transport protocol.
pub enum H2hFrame {
    SyncRequest(H2hPayload),
    SyncResponse(H2hPayload),
    DeliverySummary {
        pending_count: u8,
        /// Whether the responder believes it is the preferred router for this
        /// LPN at the time of the wake session. This is informational rather
        /// than authoritative: fallback routers may legitimately serve retained
        /// deliveries from replicas even when `preferred_router == false`.
        /// The bit exists so traces/exports/debugging can explain *why* a
        /// delayed-delivery session succeeded through a backup router.
        preferred_router: bool,
    },
    DeliveryData {
        trace_id: u64,
        message_id: [u8; 8],
        source_addr: ShortAddr,
        destination_addr: ShortAddr,
        body: Vec<u8, H2H_DELIVERY_BODY_MAX>,
    },
    DeliveryAck {
        trace_ids: Vec<u64, H2H_ACK_IDS_MAX>,
    },
    /// Router-to-router retained-delivery replica transfer. This keeps
    /// redundancy inside the same direct peer session model as sync/delivery,
    /// instead of growing a separate replication transport beside H2H.
    ///
    /// The current policy is intentionally simple: preferred/original routers
    /// may opportunistically seed reachable store-capable routers. Load-aware
    /// placement can evolve later without replacing the frame family.
    RetentionReplica {
        trace_id: u64,
        message_id: [u8; 8],
        source_addr: ShortAddr,
        destination_addr: ShortAddr,
        owner_router_addr: ShortAddr,
        body: Vec<u8, H2H_DELIVERY_BODY_MAX>,
    },
    /// Delivery/replica acknowledgements share the same compact shape: a small
    /// list of trace IDs that the receiver accepted/consumed.
    RetentionAck {
        trace_ids: Vec<u64, H2H_ACK_IDS_MAX>,
    },
    /// Tombstones clear stale retained replicas after one router has already
    /// completed delayed delivery to the target LPN. They exist because owner
    /// vs holder can diverge once replicas are seeded; explicit cleanup is more
    /// robust than hoping every replica notices delivery through ambient state.
    RetentionTombstone {
        trace_ids: Vec<u64, H2H_ACK_IDS_MAX>,
    },
    SessionDone,
}

impl H2hFrame {
    const TYPE_SYNC_REQUEST: u8 = 0x01;
    const TYPE_SYNC_RESPONSE: u8 = 0x02;
    const TYPE_DELIVERY_SUMMARY: u8 = 0x03;
    const TYPE_DELIVERY_DATA: u8 = 0x04;
    const TYPE_DELIVERY_ACK: u8 = 0x05;
    const TYPE_RETENTION_REPLICA: u8 = 0x06;
    const TYPE_RETENTION_ACK: u8 = 0x07;
    const TYPE_RETENTION_TOMBSTONE: u8 = 0x08;
    const TYPE_SESSION_DONE: u8 = 0x09;

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        if buf.len() < 2 {
            return Err(PacketError::BufferTooSmall);
        }

        buf[0] = match self {
            H2hFrame::SyncRequest(_) => Self::TYPE_SYNC_REQUEST,
            H2hFrame::SyncResponse(_) => Self::TYPE_SYNC_RESPONSE,
            H2hFrame::DeliverySummary { .. } => Self::TYPE_DELIVERY_SUMMARY,
            H2hFrame::DeliveryData { .. } => Self::TYPE_DELIVERY_DATA,
            H2hFrame::DeliveryAck { .. } => Self::TYPE_DELIVERY_ACK,
            H2hFrame::RetentionReplica { .. } => Self::TYPE_RETENTION_REPLICA,
            H2hFrame::RetentionAck { .. } => Self::TYPE_RETENTION_ACK,
            H2hFrame::RetentionTombstone { .. } => Self::TYPE_RETENTION_TOMBSTONE,
            H2hFrame::SessionDone => Self::TYPE_SESSION_DONE,
        };
        buf[1] = H2H_VERSION;

        match self {
            H2hFrame::SyncRequest(payload) | H2hFrame::SyncResponse(payload) => {
                let n = payload.serialize(&mut buf[2..])?;
                Ok(2 + n)
            }
            H2hFrame::DeliverySummary {
                pending_count,
                preferred_router,
            } => {
                if buf.len() < 4 {
                    return Err(PacketError::BufferTooSmall);
                }
                buf[2] = *pending_count;
                buf[3] = if *preferred_router { 1 } else { 0 };
                Ok(4)
            }
            H2hFrame::DeliveryData {
                trace_id,
                message_id,
                source_addr,
                destination_addr,
                body,
            } => {
                let needed = 2 + 8 + 8 + 8 + 8 + 2 + body.len();
                if buf.len() < needed {
                    return Err(PacketError::BufferTooSmall);
                }
                let mut off = 2;
                buf[off..off + 8].copy_from_slice(&trace_id.to_le_bytes());
                off += 8;
                buf[off..off + 8].copy_from_slice(message_id);
                off += 8;
                buf[off..off + 8].copy_from_slice(source_addr);
                off += 8;
                buf[off..off + 8].copy_from_slice(destination_addr);
                off += 8;
                let body_len = body.len() as u16;
                buf[off..off + 2].copy_from_slice(&body_len.to_le_bytes());
                off += 2;
                buf[off..off + body.len()].copy_from_slice(body.as_slice());
                Ok(needed)
            }
            H2hFrame::DeliveryAck { trace_ids } => {
                let needed = 3 + 8 * trace_ids.len();
                if buf.len() < needed {
                    return Err(PacketError::BufferTooSmall);
                }
                buf[2] = trace_ids.len() as u8;
                let mut off = 3;
                for trace_id in trace_ids.iter() {
                    buf[off..off + 8].copy_from_slice(&trace_id.to_le_bytes());
                    off += 8;
                }
                Ok(needed)
            }
            H2hFrame::RetentionReplica {
                trace_id,
                message_id,
                source_addr,
                destination_addr,
                owner_router_addr,
                body,
            } => {
                let needed = 2 + 8 + 8 + 8 + 8 + 8 + 2 + body.len();
                if buf.len() < needed {
                    return Err(PacketError::BufferTooSmall);
                }
                let mut off = 2;
                buf[off..off + 8].copy_from_slice(&trace_id.to_le_bytes());
                off += 8;
                buf[off..off + 8].copy_from_slice(message_id);
                off += 8;
                buf[off..off + 8].copy_from_slice(source_addr);
                off += 8;
                buf[off..off + 8].copy_from_slice(destination_addr);
                off += 8;
                buf[off..off + 8].copy_from_slice(owner_router_addr);
                off += 8;
                let body_len = body.len() as u16;
                buf[off..off + 2].copy_from_slice(&body_len.to_le_bytes());
                off += 2;
                buf[off..off + body.len()].copy_from_slice(body.as_slice());
                Ok(needed)
            }
            H2hFrame::RetentionAck { trace_ids } | H2hFrame::RetentionTombstone { trace_ids } => {
                let needed = 3 + 8 * trace_ids.len();
                if buf.len() < needed {
                    return Err(PacketError::BufferTooSmall);
                }
                buf[2] = trace_ids.len() as u8;
                let mut off = 3;
                for trace_id in trace_ids.iter() {
                    buf[off..off + 8].copy_from_slice(&trace_id.to_le_bytes());
                    off += 8;
                }
                Ok(needed)
            }
            H2hFrame::SessionDone => Ok(2),
        }
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, PacketError> {
        if buf.len() < 2 {
            return Err(PacketError::InvalidHeader);
        }
        if buf[1] != H2H_VERSION {
            return Err(PacketError::InvalidHeader);
        }

        match buf[0] {
            Self::TYPE_SYNC_REQUEST => Ok(Self::SyncRequest(H2hPayload::deserialize(&buf[2..])?)),
            Self::TYPE_SYNC_RESPONSE => Ok(Self::SyncResponse(H2hPayload::deserialize(&buf[2..])?)),
            Self::TYPE_DELIVERY_SUMMARY => {
                if buf.len() < 4 {
                    return Err(PacketError::InvalidHeader);
                }
                Ok(Self::DeliverySummary {
                    pending_count: buf[2],
                    preferred_router: buf[3] != 0,
                })
            }
            Self::TYPE_DELIVERY_DATA => {
                if buf.len() < 36 {
                    return Err(PacketError::InvalidHeader);
                }
                let mut off = 2;
                let trace_id = u64::from_le_bytes(
                    buf[off..off + 8]
                        .try_into()
                        .map_err(|_| PacketError::InvalidHeader)?,
                );
                off += 8;
                let mut message_id = [0u8; 8];
                message_id.copy_from_slice(&buf[off..off + 8]);
                off += 8;
                let mut source_addr = [0u8; 8];
                source_addr.copy_from_slice(&buf[off..off + 8]);
                off += 8;
                let mut destination_addr = [0u8; 8];
                destination_addr.copy_from_slice(&buf[off..off + 8]);
                off += 8;
                let body_len = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
                off += 2;
                if off + body_len > buf.len() || body_len > H2H_DELIVERY_BODY_MAX {
                    return Err(PacketError::InvalidHeader);
                }
                let mut body = Vec::new();
                for byte in &buf[off..off + body_len] {
                    body.push(*byte).map_err(|_| PacketError::InvalidHeader)?;
                }
                Ok(Self::DeliveryData {
                    trace_id,
                    message_id,
                    source_addr,
                    destination_addr,
                    body,
                })
            }
            Self::TYPE_DELIVERY_ACK => {
                if buf.len() < 3 {
                    return Err(PacketError::InvalidHeader);
                }
                let count = buf[2].min(H2H_ACK_IDS_MAX as u8) as usize;
                let needed = 3 + count * 8;
                if buf.len() < needed {
                    return Err(PacketError::InvalidHeader);
                }
                let mut trace_ids = Vec::new();
                let mut off = 3;
                for _ in 0..count {
                    let trace_id = u64::from_le_bytes(
                        buf[off..off + 8]
                            .try_into()
                            .map_err(|_| PacketError::InvalidHeader)?,
                    );
                    off += 8;
                    trace_ids
                        .push(trace_id)
                        .map_err(|_| PacketError::InvalidHeader)?;
                }
                Ok(Self::DeliveryAck { trace_ids })
            }
            Self::TYPE_RETENTION_REPLICA => {
                if buf.len() < 44 {
                    return Err(PacketError::InvalidHeader);
                }
                let mut off = 2;
                let trace_id = u64::from_le_bytes(
                    buf[off..off + 8]
                        .try_into()
                        .map_err(|_| PacketError::InvalidHeader)?,
                );
                off += 8;
                let mut message_id = [0u8; 8];
                message_id.copy_from_slice(&buf[off..off + 8]);
                off += 8;
                let mut source_addr = [0u8; 8];
                source_addr.copy_from_slice(&buf[off..off + 8]);
                off += 8;
                let mut destination_addr = [0u8; 8];
                destination_addr.copy_from_slice(&buf[off..off + 8]);
                off += 8;
                let mut owner_router_addr = [0u8; 8];
                owner_router_addr.copy_from_slice(&buf[off..off + 8]);
                off += 8;
                let body_len = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
                off += 2;
                if off + body_len > buf.len() || body_len > H2H_DELIVERY_BODY_MAX {
                    return Err(PacketError::InvalidHeader);
                }
                let mut body = Vec::new();
                for byte in &buf[off..off + body_len] {
                    body.push(*byte).map_err(|_| PacketError::InvalidHeader)?;
                }
                Ok(Self::RetentionReplica {
                    trace_id,
                    message_id,
                    source_addr,
                    destination_addr,
                    owner_router_addr,
                    body,
                })
            }
            Self::TYPE_RETENTION_ACK | Self::TYPE_RETENTION_TOMBSTONE => {
                if buf.len() < 3 {
                    return Err(PacketError::InvalidHeader);
                }
                let count = buf[2].min(H2H_ACK_IDS_MAX as u8) as usize;
                let needed = 3 + count * 8;
                if buf.len() < needed {
                    return Err(PacketError::InvalidHeader);
                }
                let mut trace_ids = Vec::new();
                let mut off = 3;
                for _ in 0..count {
                    let trace_id = u64::from_le_bytes(
                        buf[off..off + 8]
                            .try_into()
                            .map_err(|_| PacketError::InvalidHeader)?,
                    );
                    off += 8;
                    trace_ids
                        .push(trace_id)
                        .map_err(|_| PacketError::InvalidHeader)?;
                }
                if buf[0] == Self::TYPE_RETENTION_ACK {
                    Ok(Self::RetentionAck { trace_ids })
                } else {
                    Ok(Self::RetentionTombstone { trace_ids })
                }
            }
            Self::TYPE_SESSION_DONE => Ok(Self::SessionDone),
            _ => Err(PacketError::InvalidHeader),
        }
    }
}

impl H2hPayload {
    /// Minimum header: flags(1) + version(1) + capabilities(2) + uptime(4) + peer_count(1) = 9
    /// With pubkey:    flags(1) + version(1) + pubkey(32) + capabilities(2) + uptime(4) + peer_count(1) = 41
    const HEADER_MIN: usize = 1 + 1 + 2 + 4 + 1;
    const HEADER_WITH_PUBKEY: usize = 1 + 1 + 32 + 2 + 4 + 1;

    pub fn max_size() -> usize {
        Self::HEADER_WITH_PUBKEY + H2H_MAX_PEER_ENTRIES * PEER_INFO_SIZE
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        let has_pubkey = self.full_pubkey.is_some();
        let header_size = if has_pubkey {
            Self::HEADER_WITH_PUBKEY
        } else {
            Self::HEADER_MIN
        };
        let count = self.peer_count as usize;
        let needed = header_size + count * PEER_INFO_SIZE;
        if buf.len() < needed {
            return Err(PacketError::BufferTooSmall);
        }

        let mut off = 0;

        // Flags byte: bit 0 = has_pubkey
        buf[off] = if has_pubkey { 0x01 } else { 0x00 };
        off += 1;

        // Version byte
        buf[off] = H2H_VERSION;
        off += 1;

        // Conditional pubkey
        if let Some(ref pk) = self.full_pubkey {
            buf[off..off + 32].copy_from_slice(pk);
            off += 32;
        }

        buf[off..off + 2].copy_from_slice(&self.capabilities.to_le_bytes());
        off += 2;

        buf[off..off + 4].copy_from_slice(&self.uptime_secs.to_le_bytes());
        off += 4;

        buf[off] = self.peer_count;
        off += 1;

        for i in 0..count {
            if let Some(ref pi) = self.peers[i] {
                buf[off..off + 32].copy_from_slice(&pi.pubkey);
                off += 32;
                buf[off..off + 2].copy_from_slice(&pi.capabilities.to_le_bytes());
                off += 2;
                buf[off] = pi.hop_count;
                off += 1;
            }
        }

        Ok(off)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, PacketError> {
        if buf.len() < Self::HEADER_MIN {
            return Err(PacketError::InvalidHeader);
        }

        let mut off = 0;

        // Read flags
        let flags = buf[off];
        off += 1;

        // Read and validate version
        let version = buf[off];
        off += 1;
        if version != H2H_VERSION {
            return Err(PacketError::InvalidHeader);
        }

        let has_pubkey = (flags & 0x01) != 0;

        // Conditional pubkey
        let full_pubkey = if has_pubkey {
            if buf.len() < Self::HEADER_WITH_PUBKEY {
                return Err(PacketError::InvalidHeader);
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&buf[off..off + 32]);
            off += 32;
            Some(pk)
        } else {
            None
        };

        let capabilities = u16::from_le_bytes([buf[off], buf[off + 1]]);
        off += 2;

        let uptime_secs = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        off += 4;

        let peer_count = buf[off].min(H2H_MAX_PEER_ENTRIES as u8);
        off += 1;

        let needed = off + (peer_count as usize) * PEER_INFO_SIZE;
        if buf.len() < needed {
            return Err(PacketError::InvalidHeader);
        }

        const NONE: Option<PeerInfo> = None;
        let mut peers = [NONE; H2H_MAX_PEER_ENTRIES];

        for i in 0..peer_count as usize {
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&buf[off..off + 32]);
            off += 32;

            let caps = u16::from_le_bytes([buf[off], buf[off + 1]]);
            off += 2;

            let hop_count = buf[off];
            off += 1;

            peers[i] = Some(PeerInfo {
                pubkey,
                capabilities: caps,
                hop_count,
            });
        }

        Ok(H2hPayload {
            full_pubkey,
            capabilities,
            uptime_secs,
            peers,
            peer_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::H2H_CYCLE_SECS;

    fn short(seed: u8) -> ShortAddr {
        [seed, 0, 0, 0, 0, 0, 0, 0]
    }

    fn pubkey(seed: u8) -> PubKey {
        [seed; 32]
    }

    fn payload_with_peer_count(peer_count: usize, include_pubkey: bool) -> H2hPayload {
        const NONE: Option<PeerInfo> = None;
        let mut peers = [NONE; H2H_MAX_PEER_ENTRIES];

        for i in 0..peer_count.min(H2H_MAX_PEER_ENTRIES) {
            peers[i] = Some(PeerInfo {
                pubkey: pubkey((i + 1) as u8),
                capabilities: 0x1000 + i as u16,
                hop_count: i as u8,
            });
        }

        H2hPayload {
            full_pubkey: include_pubkey.then(|| pubkey(0xAA)),
            capabilities: 0xBEEF,
            uptime_secs: 42,
            peers,
            peer_count: peer_count as u8,
        }
    }

    #[test]
    fn initiator_selection_is_lexicographic() {
        let lower = short(0x01);
        let higher = short(0x02);

        assert!(is_initiator(&lower, &higher));
        assert!(!is_initiator(&higher, &lower));
    }

    #[test]
    fn slot_offset_is_symmetric_and_in_range() {
        let a = short(0x11);
        let b = short(0x77);

        let ab = slot_offset(&a, &b);
        let ba = slot_offset(&b, &a);

        assert_eq!(ab, ba);
        assert!(ab < H2H_CYCLE_SECS);
    }

    #[test]
    fn payload_roundtrip_with_full_pubkey() {
        let payload = payload_with_peer_count(2, true);
        let mut buf = [0u8; 512];

        let written = payload.serialize(&mut buf).unwrap();
        let decoded = H2hPayload::deserialize(&buf[..written]).unwrap();

        assert_eq!(decoded.full_pubkey, payload.full_pubkey);
        assert_eq!(decoded.capabilities, payload.capabilities);
        assert_eq!(decoded.uptime_secs, payload.uptime_secs);
        assert_eq!(decoded.peer_count, payload.peer_count);

        for i in 0..payload.peer_count as usize {
            let expected = payload.peers[i].as_ref().unwrap();
            let actual = decoded.peers[i].as_ref().unwrap();
            assert_eq!(actual.pubkey, expected.pubkey);
            assert_eq!(actual.capabilities, expected.capabilities);
            assert_eq!(actual.hop_count, expected.hop_count);
        }
    }

    #[test]
    fn payload_roundtrip_without_full_pubkey() {
        let payload = payload_with_peer_count(3, false);
        let mut buf = [0u8; 512];

        let written = payload.serialize(&mut buf).unwrap();
        let decoded = H2hPayload::deserialize(&buf[..written]).unwrap();

        assert_eq!(decoded.full_pubkey, None);
        assert_eq!(decoded.capabilities, payload.capabilities);
        assert_eq!(decoded.uptime_secs, payload.uptime_secs);
        assert_eq!(decoded.peer_count, payload.peer_count);
    }

    #[test]
    fn deserialize_rejects_truncated_payload() {
        let payload = payload_with_peer_count(1, true);
        let mut buf = [0u8; 512];

        let written = payload.serialize(&mut buf).unwrap();

        assert!(matches!(
            H2hPayload::deserialize(&buf[..written - 1]),
            Err(PacketError::InvalidHeader)
        ));
    }

    #[test]
    fn deserialize_clamps_peer_count_to_capacity() {
        let payload = payload_with_peer_count(H2H_MAX_PEER_ENTRIES, false);
        let mut buf = [0u8; 512];
        let written = payload.serialize(&mut buf).unwrap();

        let peer_count_offset = 1 + 1 + 2 + 4;
        buf[peer_count_offset] = (H2H_MAX_PEER_ENTRIES as u8).saturating_add(5);

        let decoded = H2hPayload::deserialize(&buf[..written]).unwrap();

        assert_eq!(decoded.peer_count as usize, H2H_MAX_PEER_ENTRIES);
        assert!(decoded.peers[H2H_MAX_PEER_ENTRIES - 1].is_some());
    }
}
