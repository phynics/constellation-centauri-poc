use crate::crypto::identity::{ShortAddr, Signature};

pub const PACKET_TYPE_HEARTBEAT: u8 = 0x01;
pub const PACKET_TYPE_DATA: u8 = 0x02;
pub const PACKET_TYPE_DATA_ENCRYPTED: u8 = 0x03;
pub const PACKET_TYPE_ANNOUNCE: u8 = 0x04;
pub const PACKET_TYPE_ACK: u8 = 0x05;

pub const FLAG_ACK_REQUESTED: u8 = 0b0000_0001;
pub const FLAG_FRAGMENTED: u8 = 0b0000_0010;
pub const FLAG_BROADCAST: u8 = 0b0000_0100;

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

// Serialization implementation in Phase 1.5.
