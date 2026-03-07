/// Transport-layer address for a peer.
///
/// Currently only BLE is supported. WiFi and LoRa will be added post-PoC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportAddr {
    pub addr_type: u8, // 0 = BLE, 1 = WiFi (future), 2 = LoRa (future)
    pub addr: [u8; 6], // BLE MAC address (6 bytes)
}

impl TransportAddr {
    /// Create a BLE transport address.
    pub const fn ble(mac: [u8; 6]) -> Self {
        Self { addr_type: 0, addr: mac }
    }
}
