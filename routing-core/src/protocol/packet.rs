//! Routed mesh packet header and builder helpers.
//!
//! Purpose: define the signed outer packet header and the shared helpers that
//! build and parse routed mesh packets.
//!
//! Design decisions:
//! - Keep packet layout and signature handling in shared core so all hosts emit
//!   and verify the same outer wire format.
//! - Maintain explicit packet families for heartbeat, infra, app, announce, and
//!   ack traffic instead of host-specific ad hoc tagging.

use crate::config::{BROADCAST_ADDR, DEFAULT_TTL, HEADER_SIZE, PROTOCOL_VERSION};
use crate::crypto::identity::{verify, NodeIdentity, ShortAddr, Signature};
use rand_core::RngCore;

pub const PACKET_TYPE_HEARTBEAT: u8 = 0x01;
pub const PACKET_TYPE_FRAME_INFRA: u8 = 0x02;
pub const PACKET_TYPE_FRAME_APP: u8 = 0x03;
pub const PACKET_TYPE_ANNOUNCE: u8 = 0x04;
pub const PACKET_TYPE_ACK: u8 = 0x05;

// Backwards-compatible aliases while call sites are migrated.
pub const PACKET_TYPE_DATA: u8 = PACKET_TYPE_FRAME_INFRA;
pub const PACKET_TYPE_DATA_ENCRYPTED: u8 = PACKET_TYPE_FRAME_APP;

pub const FLAG_ACK_REQUESTED: u8 = 0b0000_0001;
pub const FLAG_FRAGMENTED: u8 = 0b0000_0010;
pub const FLAG_BROADCAST: u8 = 0b0000_0100;

#[derive(Debug)]
pub enum PacketError {
    BufferTooSmall,
    InvalidHeader,
    InvalidSignature,
}

#[derive(Clone)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: u8,
    pub flags: u8,
    pub ttl: u8,
    pub hop_count: u8,
    pub src: ShortAddr,
    pub dst: ShortAddr,
    pub message_id: [u8; 8],
    pub signature: Signature,
}

impl PacketHeader {
    /// Serialize the header into a byte buffer.
    ///
    /// Header layout (92 bytes):
    /// - version (4 bits) | packet_type (4 bits): 1 byte
    /// - flags: 1 byte
    /// - ttl: 1 byte
    /// - hop_count: 1 byte
    /// - src: 8 bytes
    /// - dst: 8 bytes
    /// - message_id: 8 bytes
    /// - signature: 64 bytes
    ///
    /// Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, PacketError> {
        if buf.len() < HEADER_SIZE {
            return Err(PacketError::BufferTooSmall);
        }

        let mut offset = 0;

        // Byte 0: version (upper 4 bits) | packet_type (lower 4 bits)
        buf[offset] = (self.version << 4) | (self.packet_type & 0x0F);
        offset += 1;

        // Byte 1: flags
        buf[offset] = self.flags;
        offset += 1;

        // Byte 2: ttl
        buf[offset] = self.ttl;
        offset += 1;

        // Byte 3: hop_count
        buf[offset] = self.hop_count;
        offset += 1;

        // Bytes 4-11: src (8 bytes)
        buf[offset..offset + 8].copy_from_slice(&self.src);
        offset += 8;

        // Bytes 12-19: dst (8 bytes)
        buf[offset..offset + 8].copy_from_slice(&self.dst);
        offset += 8;

        // Bytes 20-27: message_id (8 bytes)
        buf[offset..offset + 8].copy_from_slice(&self.message_id);
        offset += 8;

        // Bytes 28-91: signature (64 bytes)
        buf[offset..offset + 64].copy_from_slice(&self.signature);
        offset += 64;

        Ok(offset)
    }

    /// Deserialize a header from a byte buffer.
    ///
    /// Returns the parsed header and a slice to the remaining payload.
    pub fn deserialize(buf: &[u8]) -> Result<(PacketHeader, &[u8]), PacketError> {
        if buf.len() < HEADER_SIZE {
            return Err(PacketError::InvalidHeader);
        }

        let mut offset = 0;

        // Byte 0: version | packet_type
        let version = (buf[offset] >> 4) & 0x0F;
        let packet_type = buf[offset] & 0x0F;
        offset += 1;

        // Byte 1: flags
        let flags = buf[offset];
        offset += 1;

        // Byte 2: ttl
        let ttl = buf[offset];
        offset += 1;

        // Byte 3: hop_count
        let hop_count = buf[offset];
        offset += 1;

        // Bytes 4-11: src
        let mut src = [0u8; 8];
        src.copy_from_slice(&buf[offset..offset + 8]);
        offset += 8;

        // Bytes 12-19: dst
        let mut dst = [0u8; 8];
        dst.copy_from_slice(&buf[offset..offset + 8]);
        offset += 8;

        // Bytes 20-27: message_id
        let mut message_id = [0u8; 8];
        message_id.copy_from_slice(&buf[offset..offset + 8]);
        offset += 8;

        // Bytes 28-91: signature
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[offset..offset + 64]);
        offset += 64;

        let header = PacketHeader {
            version,
            packet_type,
            flags,
            ttl,
            hop_count,
            src,
            dst,
            message_id,
            signature,
        };

        let payload = &buf[offset..];

        Ok((header, payload))
    }

    /// Sign the packet header and payload.
    ///
    /// Signature covers: [version, type, flags, src, dst, message_id, payload]
    /// Note: hop_count and ttl are NOT signed since relays mutate them.
    pub fn sign(&mut self, identity: &NodeIdentity, payload: &[u8]) {
        let signable_data = self.build_signable_data(payload);
        self.signature = identity.sign(&signable_data);
    }

    /// Verify the packet signature.
    pub fn verify(&self, sender_pubkey: &[u8; 32], payload: &[u8]) -> bool {
        let signable_data = self.build_signable_data(payload);
        verify(sender_pubkey, &signable_data, &self.signature)
    }

    /// Build the data that should be signed/verified.
    ///
    /// Includes all header fields except ttl, hop_count, and signature, plus payload.
    fn build_signable_data(&self, payload: &[u8]) -> heapless::Vec<u8, 256> {
        let mut data = heapless::Vec::new();

        // version | packet_type
        let _ = data.push((self.version << 4) | (self.packet_type & 0x0F));

        // flags
        let _ = data.push(self.flags);

        // src (8 bytes)
        let _ = data.extend_from_slice(&self.src);

        // dst (8 bytes)
        let _ = data.extend_from_slice(&self.dst);

        // message_id (8 bytes)
        let _ = data.extend_from_slice(&self.message_id);

        // payload (variable)
        let _ = data.extend_from_slice(payload);

        data
    }
}

/// Helper to build a complete packet (header + payload) with an explicit
/// caller-provided message ID and sign it.
///
/// Returns the number of bytes written to `buf`.
pub fn build_packet_with_message_id(
    identity: &NodeIdentity,
    packet_type: u8,
    flags: u8,
    dst: ShortAddr,
    message_id: [u8; 8],
    payload: &[u8],
    buf: &mut [u8],
) -> Result<usize, PacketError> {
    if buf.len() < HEADER_SIZE + payload.len() {
        return Err(PacketError::BufferTooSmall);
    }

    let mut header = PacketHeader {
        version: PROTOCOL_VERSION,
        packet_type,
        flags,
        ttl: DEFAULT_TTL,
        hop_count: 0,
        src: *identity.short_addr(),
        dst,
        message_id,
        signature: [0u8; 64], // Will be filled by sign()
    };

    // Sign the header + payload
    header.sign(identity, payload);

    // Serialize header
    let header_len = header.serialize(buf)?;

    // Append payload
    buf[header_len..header_len + payload.len()].copy_from_slice(payload);

    Ok(header_len + payload.len())
}

/// Helper to build a complete packet and generate its message ID from an RNG.
pub fn build_packet_with_rng(
    identity: &NodeIdentity,
    packet_type: u8,
    flags: u8,
    dst: ShortAddr,
    rng: &mut impl RngCore,
    payload: &[u8],
    buf: &mut [u8],
) -> Result<usize, PacketError> {
    let mut message_id = [0u8; 8];
    rng.fill_bytes(&mut message_id);
    build_packet_with_message_id(identity, packet_type, flags, dst, message_id, payload, buf)
}

/// Backwards-compatible packet builder name using RNG-backed message IDs.
pub fn build_packet(
    identity: &NodeIdentity,
    packet_type: u8,
    flags: u8,
    dst: ShortAddr,
    rng: &mut impl RngCore,
    payload: &[u8],
    buf: &mut [u8],
) -> Result<usize, PacketError> {
    build_packet_with_rng(identity, packet_type, flags, dst, rng, payload, buf)
}

/// Helper to build a broadcast packet with an explicit message ID.
pub fn build_broadcast_packet_with_message_id(
    identity: &NodeIdentity,
    packet_type: u8,
    flags: u8,
    message_id: [u8; 8],
    payload: &[u8],
    buf: &mut [u8],
) -> Result<usize, PacketError> {
    build_packet_with_message_id(
        identity,
        packet_type,
        flags | FLAG_BROADCAST,
        BROADCAST_ADDR,
        message_id,
        payload,
        buf,
    )
}

/// Helper to build a broadcast packet with an RNG-backed message ID.
pub fn build_broadcast_packet_with_rng(
    identity: &NodeIdentity,
    packet_type: u8,
    flags: u8,
    rng: &mut impl RngCore,
    payload: &[u8],
    buf: &mut [u8],
) -> Result<usize, PacketError> {
    build_packet_with_rng(
        identity,
        packet_type,
        flags | FLAG_BROADCAST,
        BROADCAST_ADDR,
        rng,
        payload,
        buf,
    )
}

/// Backwards-compatible broadcast builder name using RNG-backed message IDs.
pub fn build_broadcast_packet(
    identity: &NodeIdentity,
    packet_type: u8,
    flags: u8,
    rng: &mut impl RngCore,
    payload: &[u8],
    buf: &mut [u8],
) -> Result<usize, PacketError> {
    build_broadcast_packet_with_rng(identity, packet_type, flags, rng, payload, buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{impls, Error, RngCore};

    struct FixedRng {
        next: [u8; 8],
    }

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            impls::next_u32_via_fill(self)
        }

        fn next_u64(&mut self) -> u64 {
            impls::next_u64_via_fill(self)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for (idx, byte) in dest.iter_mut().enumerate() {
                *byte = self.next[idx % self.next.len()];
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn identity(seed: u8) -> NodeIdentity {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        secret[31] = seed.wrapping_add(0x80);
        NodeIdentity::from_bytes(&secret)
    }

    #[test]
    fn header_serialize_deserialize_roundtrip() {
        let header = PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type: PACKET_TYPE_DATA,
            flags: FLAG_ACK_REQUESTED,
            ttl: 9,
            hop_count: 2,
            src: [0x11; 8],
            dst: [0x22; 8],
            message_id: [0x33; 8],
            signature: [0x44; 64],
        };
        let mut buf = [0u8; HEADER_SIZE];

        let written = header.serialize(&mut buf).unwrap();
        let (decoded, payload) = PacketHeader::deserialize(&buf[..written]).unwrap();

        assert_eq!(written, HEADER_SIZE);
        assert!(payload.is_empty());
        assert_eq!(decoded.version, header.version);
        assert_eq!(decoded.packet_type, header.packet_type);
        assert_eq!(decoded.flags, header.flags);
        assert_eq!(decoded.ttl, header.ttl);
        assert_eq!(decoded.hop_count, header.hop_count);
        assert_eq!(decoded.src, header.src);
        assert_eq!(decoded.dst, header.dst);
        assert_eq!(decoded.message_id, header.message_id);
        assert_eq!(decoded.signature, header.signature);
    }

    #[test]
    fn build_packet_with_message_id_roundtrips_and_verifies() {
        let identity = identity(0x01);
        let dst = [0xAB; 8];
        let message_id = [0x55; 8];
        let payload = b"hello-mesh";
        let mut buf = [0u8; 256];

        let written = build_packet_with_message_id(
            &identity,
            PACKET_TYPE_DATA,
            FLAG_ACK_REQUESTED,
            dst,
            message_id,
            payload,
            &mut buf,
        )
        .unwrap();

        let (header, decoded_payload) = PacketHeader::deserialize(&buf[..written]).unwrap();

        assert_eq!(decoded_payload, payload);
        assert_eq!(header.dst, dst);
        assert_eq!(header.message_id, message_id);
        assert!(header.verify(&identity.pubkey(), decoded_payload));
    }

    #[test]
    fn signature_fails_when_payload_is_modified() {
        let identity = identity(0x02);
        let payload = b"original";
        let mut buf = [0u8; 256];

        let written = build_packet_with_message_id(
            &identity,
            PACKET_TYPE_DATA,
            0,
            [0xBC; 8],
            [0x66; 8],
            payload,
            &mut buf,
        )
        .unwrap();

        let (header, _) = PacketHeader::deserialize(&buf[..written]).unwrap();
        assert!(!header.verify(&identity.pubkey(), b"tampered"));
    }

    #[test]
    fn signature_ignores_hop_count_changes() {
        let identity = identity(0x03);
        let payload = b"relayable";
        let mut buf = [0u8; 256];

        let written = build_packet_with_message_id(
            &identity,
            PACKET_TYPE_DATA,
            0,
            [0xCD; 8],
            [0x77; 8],
            payload,
            &mut buf,
        )
        .unwrap();

        let (mut header, decoded_payload) = PacketHeader::deserialize(&buf[..written]).unwrap();
        header.hop_count = header.hop_count.saturating_add(1);

        assert!(header.verify(&identity.pubkey(), decoded_payload));
    }

    #[test]
    fn broadcast_builder_sets_broadcast_fields() {
        let identity = identity(0x04);
        let mut buf = [0u8; 256];

        let written = build_broadcast_packet_with_message_id(
            &identity,
            PACKET_TYPE_HEARTBEAT,
            FLAG_ACK_REQUESTED,
            [0x88; 8],
            b"hb",
            &mut buf,
        )
        .unwrap();

        let (header, payload) = PacketHeader::deserialize(&buf[..written]).unwrap();
        assert_eq!(payload, b"hb");
        assert_eq!(header.dst, BROADCAST_ADDR);
        assert_ne!(header.flags & FLAG_BROADCAST, 0);
        assert_eq!(header.message_id, [0x88; 8]);
    }

    #[test]
    fn rng_backed_builder_uses_rng_message_id() {
        let identity = identity(0x05);
        let mut rng = FixedRng {
            next: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut buf = [0u8; 256];

        let written = build_packet(
            &identity,
            PACKET_TYPE_DATA,
            0,
            [0xDE; 8],
            &mut rng,
            b"payload",
            &mut buf,
        )
        .unwrap();

        let (header, _) = PacketHeader::deserialize(&buf[..written]).unwrap();
        assert_eq!(header.message_id, [1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
