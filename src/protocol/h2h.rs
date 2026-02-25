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

use sha2::{Sha256, Digest};

use crate::config::{H2H_CYCLE_SECS, H2H_MAX_PEER_ENTRIES};
use crate::crypto::identity::{PubKey, ShortAddr};
use crate::protocol::packet::PacketError;

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
    pub short_addr: ShortAddr,
    pub capabilities: u16,
    pub hop_count: u8,
}

const PEER_INFO_SIZE: usize = 8 + 2 + 1; // 11

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

impl H2hPayload {
    /// Minimum header: flags(1) + capabilities(2) + uptime(4) + peer_count(1) = 8
    /// With pubkey:    flags(1) + pubkey(32) + capabilities(2) + uptime(4) + peer_count(1) = 40
    const HEADER_MIN: usize = 1 + 2 + 4 + 1;
    const HEADER_WITH_PUBKEY: usize = 1 + 32 + 2 + 4 + 1;

    pub fn max_size() -> usize {
        Self::HEADER_WITH_PUBKEY + H2H_MAX_PEER_ENTRIES * PEER_INFO_SIZE
    }

    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        let has_pubkey = self.full_pubkey.is_some();
        let header_size = if has_pubkey { Self::HEADER_WITH_PUBKEY } else { Self::HEADER_MIN };
        let count = self.peer_count as usize;
        let needed = header_size + count * PEER_INFO_SIZE;
        if buf.len() < needed {
            return Err(PacketError::BufferTooSmall);
        }

        let mut off = 0;

        // Flags byte: bit 0 = has_pubkey
        buf[off] = if has_pubkey { 0x01 } else { 0x00 };
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
                buf[off..off + 8].copy_from_slice(&pi.short_addr);
                off += 8;
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
            let mut short_addr = [0u8; 8];
            short_addr.copy_from_slice(&buf[off..off + 8]);
            off += 8;

            let caps = u16::from_le_bytes([buf[off], buf[off + 1]]);
            off += 2;

            let hop_count = buf[off];
            off += 1;

            peers[i] = Some(PeerInfo {
                short_addr,
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
