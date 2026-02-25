/// Constellation mesh BLE service UUID.
/// Custom 128-bit UUID for the mesh network service.
pub const CONSTELLATION_SERVICE_UUID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1,
];

/// Maximum BLE packet size for mesh packets.
pub const MAX_GATT_PACKET: usize = 512;

/// BLE packet buffer type.
pub type PacketBuf = heapless::Vec<u8, MAX_GATT_PACKET>;

/// BLE transport errors.
#[derive(Debug)]
pub enum BleError {
    InvalidTransport,
    ConnectionFailed,
    SendFailed,
    ReceiveFailed,
    BufferTooSmall,
}
