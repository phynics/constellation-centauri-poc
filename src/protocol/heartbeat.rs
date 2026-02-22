use crate::crypto::identity::PubKey;
use crate::config::BLOOM_FILTER_BYTES;

pub struct HeartbeatPayload {
    pub full_pubkey: PubKey,
    pub capabilities: u16,
    pub uptime_secs: u32,
    pub bloom_filter: [u8; BLOOM_FILTER_BYTES],
    pub bloom_generation: u8,
}

// Serialization implementation in Phase 1.6.
