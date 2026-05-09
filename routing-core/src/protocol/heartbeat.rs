//! Heartbeat payload format used for periodic topology advertisements.

use crate::config::BLOOM_FILTER_BYTES;
use crate::crypto::identity::PubKey;
use crate::protocol::packet::PacketError;

pub struct HeartbeatPayload {
    pub full_pubkey: PubKey,
    pub capabilities: u16,
    pub uptime_secs: u32,
    pub bloom_filter: [u8; BLOOM_FILTER_BYTES],
    pub bloom_generation: u8,
}

impl HeartbeatPayload {
    /// Serialize heartbeat payload to bytes.
    ///
    /// Layout (~71 bytes):
    /// - full_pubkey: 32 bytes
    /// - capabilities: 2 bytes (little-endian)
    /// - uptime_secs: 4 bytes (little-endian)
    /// - bloom_filter: 32 bytes
    /// - bloom_generation: 1 byte
    ///
    /// Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        const PAYLOAD_SIZE: usize = 32 + 2 + 4 + BLOOM_FILTER_BYTES + 1;

        if buf.len() < PAYLOAD_SIZE {
            return Err(PacketError::BufferTooSmall);
        }

        let mut offset = 0;

        // full_pubkey: 32 bytes
        buf[offset..offset + 32].copy_from_slice(&self.full_pubkey);
        offset += 32;

        // capabilities: 2 bytes (little-endian)
        buf[offset..offset + 2].copy_from_slice(&self.capabilities.to_le_bytes());
        offset += 2;

        // uptime_secs: 4 bytes (little-endian)
        buf[offset..offset + 4].copy_from_slice(&self.uptime_secs.to_le_bytes());
        offset += 4;

        // bloom_filter: 32 bytes
        buf[offset..offset + BLOOM_FILTER_BYTES].copy_from_slice(&self.bloom_filter);
        offset += BLOOM_FILTER_BYTES;

        // bloom_generation: 1 byte
        buf[offset] = self.bloom_generation;
        offset += 1;

        Ok(offset)
    }

    /// Deserialize heartbeat payload from bytes.
    pub fn deserialize(buf: &[u8]) -> Result<HeartbeatPayload, PacketError> {
        const PAYLOAD_SIZE: usize = 32 + 2 + 4 + BLOOM_FILTER_BYTES + 1;

        if buf.len() < PAYLOAD_SIZE {
            return Err(PacketError::InvalidHeader);
        }

        let mut offset = 0;

        // full_pubkey: 32 bytes
        let mut full_pubkey = [0u8; 32];
        full_pubkey.copy_from_slice(&buf[offset..offset + 32]);
        offset += 32;

        // capabilities: 2 bytes (little-endian)
        let capabilities = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        offset += 2;

        // uptime_secs: 4 bytes (little-endian)
        let uptime_secs = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        offset += 4;

        // bloom_filter: 32 bytes
        let mut bloom_filter = [0u8; BLOOM_FILTER_BYTES];
        bloom_filter.copy_from_slice(&buf[offset..offset + BLOOM_FILTER_BYTES]);
        offset += BLOOM_FILTER_BYTES;

        // bloom_generation: 1 byte
        let bloom_generation = buf[offset];

        Ok(HeartbeatPayload {
            full_pubkey,
            capabilities,
            uptime_secs,
            bloom_filter,
            bloom_generation,
        })
    }

    /// Get the serialized size of a heartbeat payload.
    pub const fn size() -> usize {
        32 + 2 + 4 + BLOOM_FILTER_BYTES + 1
    }
}
