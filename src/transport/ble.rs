use crate::crypto::identity::ShortAddr;

/// Constellation mesh BLE service UUID.
/// Custom 128-bit UUID for the mesh network service.
pub const CONSTELLATION_SERVICE_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1,
];

/// Characteristic UUID for full heartbeat payload (read).
pub const HEARTBEAT_CHAR_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf2,
];

/// Characteristic UUID for mesh packet exchange (write/notify).
pub const PACKET_CHAR_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf3,
];

/// Maximum BLE advertising payload size (legacy advertising).
pub const MAX_ADV_PAYLOAD: usize = 31;

/// Maximum BLE packet size for GATT characteristics.
/// ESP32 supports up to 512 bytes per GATT characteristic.
pub const MAX_GATT_PACKET: usize = 512;

/// BLE packet buffer type.
pub type PacketBuf = heapless::Vec<u8, MAX_GATT_PACKET>;

/// Minimal advertising beacon payload.
///
/// Layout (10 bytes):
/// - service_uuid_16: 2 bytes (short form of constellation service)
/// - short_addr: 8 bytes
///
/// Peers use this to identify constellation nodes and obtain their ShortAddr.
/// They then connect via GATT to read the full heartbeat.
#[derive(Clone, Copy)]
pub struct AdvBeacon {
    pub service_uuid_16: u16, // 0x1234 (shortened from full UUID)
    pub short_addr: ShortAddr,
}

impl AdvBeacon {
    pub const SIZE: usize = 2 + 8;

    /// Create a new advertising beacon.
    pub fn new(short_addr: ShortAddr) -> Self {
        Self {
            service_uuid_16: 0x1234,
            short_addr,
        }
    }

    /// Serialize beacon to bytes for advertising payload.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        if buf.len() < Self::SIZE {
            return 0;
        }

        let mut offset = 0;

        // service_uuid_16 (little-endian)
        buf[offset..offset + 2].copy_from_slice(&self.service_uuid_16.to_le_bytes());
        offset += 2;

        // short_addr
        buf[offset..offset + 8].copy_from_slice(&self.short_addr);
        offset += 8;

        offset
    }

    /// Deserialize beacon from advertising payload.
    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }

        let mut offset = 0;

        let service_uuid_16 = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        offset += 2;

        let mut short_addr = [0u8; 8];
        short_addr.copy_from_slice(&buf[offset..offset + 8]);

        Some(Self {
            service_uuid_16,
            short_addr,
        })
    }
}

/// BLE transport errors.
#[derive(Debug)]
pub enum BleError {
    InvalidTransport,
    ConnectionFailed,
    SendFailed,
    ReceiveFailed,
    BufferTooSmall,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adv_beacon_serialization() {
        let short_addr = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let beacon = AdvBeacon::new(short_addr);

        let mut buf = [0u8; 32];
        let len = beacon.serialize(&mut buf);

        assert_eq!(len, AdvBeacon::SIZE);

        let parsed = AdvBeacon::deserialize(&buf[..len]).unwrap();
        assert_eq!(parsed.service_uuid_16, 0x1234);
        assert_eq!(parsed.short_addr, short_addr);
    }
}
