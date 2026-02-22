use crate::config::HEARTBEAT_INTERVAL_SECS;
use crate::crypto::identity::ShortAddr;
use crate::protocol::heartbeat::HeartbeatPayload;
use crate::routing::table::RoutingTable;
use crate::transport::TransportAddr;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
// use embassy_time::{Duration, Timer}; // Temporarily disabled - needs timer driver setup

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
    pub service_uuid_16: u16,  // 0x1234 (shortened from full UUID)
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

/// BLE advertising task.
///
/// Broadcasts minimal advertising beacon every HEARTBEAT_INTERVAL.
/// Peers discover this beacon and connect to read full heartbeat via GATT.
///
/// Note: This is a skeleton for Phase 3. Actual implementation requires
/// trouble-host BLE controller integration, which will be completed in Phase 5.
pub async fn ble_advertise_task(
    short_addr: ShortAddr,
    // TODO: Add BLE controller reference when integrating trouble-host
) {
    let beacon = AdvBeacon::new(short_addr);
    let mut adv_buf = [0u8; MAX_ADV_PAYLOAD];
    let _adv_len = beacon.serialize(&mut adv_buf);

    loop {
        // TODO: Set advertising data using trouble-host API
        // set_advertising_data(&adv_buf[..adv_len]);
        // start_advertising();

        log::info!("BLE advertising beacon for {short_addr:x?}");

        // Yield to allow other tasks to run
        // TODO: Replace with Timer::after when timer driver is configured
        embassy_futures::yield_now().await;
    }
}

/// BLE scanning task.
///
/// Continuously scans for advertising beacons from other constellation nodes.
/// When a beacon is discovered:
/// 1. Extract the peer's ShortAddr
/// 2. Connect to the peer
/// 3. Read full heartbeat from GATT characteristic
/// 4. Update routing table
///
/// Note: This is a skeleton for Phase 3. Actual implementation requires
/// trouble-host BLE controller integration, which will be completed in Phase 5.
pub async fn ble_scan_task(
    _routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
    // TODO: Add BLE controller reference when integrating trouble-host
) {
    loop {
        // TODO: Scan for advertising packets using trouble-host API
        // let (adv_data, peer_mac) = scan_next().await;

        // Parse advertising beacon
        // if let Some(beacon) = AdvBeacon::deserialize(&adv_data) {
        //     log::info!("Discovered peer {:x?} at BLE addr {:x?}", beacon.short_addr, peer_mac);
        //
        //     // Connect to peer and read full heartbeat via GATT
        //     // let connection = connect(peer_mac).await;
        //     // let heartbeat_data = gatt_read(connection, HEARTBEAT_CHAR_UUID).await;
        //     // let heartbeat = HeartbeatPayload::deserialize(&heartbeat_data)?;
        //
        //     // Update routing table
        //     // let transport_addr = TransportAddr::ble(peer_mac);
        //     // let mut table = routing_table.lock().await;
        //     // table.update_peer(&heartbeat, transport_addr, now_ticks());
        // }

        embassy_futures::yield_now().await;
    }
}

/// BLE GATT server task.
///
/// Handles GATT operations:
/// - Read requests on HEARTBEAT_CHAR: Return serialized HeartbeatPayload
/// - Write requests on PACKET_CHAR: Receive incoming mesh packets
/// - Notify on PACKET_CHAR: Send outgoing mesh packets to connected peers
///
/// Note: This is a skeleton for Phase 3. Actual implementation requires
/// trouble-host GATT server integration, which will be completed in Phase 5.
pub async fn ble_gatt_task(
    _heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
    _incoming_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
    _outgoing_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
    // TODO: Add GATT server reference when integrating trouble-host
) {
    loop {
        // TODO: Handle GATT events using trouble-host API
        //
        // match gatt_event().await {
        //     GattEvent::Read { handle, offset } => {
        //         if handle == HEARTBEAT_CHAR_HANDLE {
        //             let hb = heartbeat.lock().await;
        //             let mut buf = [0u8; 128];
        //             let len = hb.serialize(&mut buf).unwrap();
        //             gatt_respond_read(&buf[..len]);
        //         }
        //     }
        //     GattEvent::Write { handle, data } => {
        //         if handle == PACKET_CHAR_HANDLE {
        //             // Received incoming mesh packet
        //             let mut packet = PacketBuf::new();
        //             packet.extend_from_slice(data).ok();
        //             incoming_packets.send(packet).await;
        //         }
        //     }
        //     GattEvent::Subscribed { handle } => {
        //         // Peer subscribed to notifications
        //         log::info!("Peer subscribed to packet notifications");
        //     }
        // }
        //
        // // Send outgoing packets as notifications
        // if let Ok(packet) = outgoing_packets.try_receive() {
        //     gatt_notify(PACKET_CHAR_HANDLE, &packet);
        // }

        embassy_futures::yield_now().await;
    }
}

/// BLE connection manager.
///
/// Maintains active connections to peers and handles connection lifecycle.
/// When routing needs to send a packet to a peer:
/// 1. Check if already connected
/// 2. If not, initiate connection using peer's BLE MAC from TransportAddr
/// 3. Write packet to peer's PACKET_CHAR via GATT
/// 4. Optionally keep connection alive or disconnect after timeout
///
/// Note: This is a skeleton for Phase 3. Actual implementation requires
/// trouble-host connection management, which will be completed in Phase 5.
pub struct ConnectionManager {
    // TODO: Track active connections
    // connections: heapless::Vec<Connection, MAX_CONNECTIONS>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            // connections: heapless::Vec::new(),
        }
    }

    /// Send a packet to a peer via BLE GATT.
    ///
    /// If not connected, initiates connection first.
    /// Writes packet to peer's PACKET_CHAR characteristic.
    pub async fn send_packet(
        &mut self,
        peer_addr: &TransportAddr,
        packet: &[u8],
    ) -> Result<(), BleError> {
        if peer_addr.addr_type != 0 {
            return Err(BleError::InvalidTransport);
        }

        // TODO: Implement connection and send logic
        // let connection = self.get_or_connect(&peer_addr.addr).await?;
        // gatt_write(connection, PACKET_CHAR_UUID, packet).await?;

        log::info!("Sent packet ({} bytes) to BLE peer {:x?}", packet.len(), peer_addr.addr);

        Ok(())
    }

    /// Get existing connection or create new one.
    async fn get_or_connect(&mut self, _mac: &[u8; 6]) -> Result<(), BleError> {
        // TODO: Check if already connected
        // if let Some(conn) = self.connections.iter().find(|c| c.mac == *mac) {
        //     return Ok(conn);
        // }

        // TODO: Initiate new connection
        // let connection = ble_connect(mac).await?;
        // self.connections.push(connection).ok();

        Ok(())
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
