#![allow(dead_code)]

//! macOS BLE bindings for shared networking traits.
//!
//! Purpose: implement shared discovery and H2H networking contracts on top of
//! CoreBluetooth/L2CAP abstractions exposed by `blew`.
//!
//! Design decisions:
//! - Keep CoreBluetooth session handling and device-ID translation in the host
//!   crate while shared H2H semantics remain in `routing-core`.
//! - Feed discovery parsing through shared-core onboarding helpers instead of
//!   inventing a companion-only discovery model.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use blew::l2cap::{L2capChannel, Psm};
use blew::{Central, DeviceId};
use routing_core::network::{
    DiscoveryEvent, H2hInitiator, H2hResponder, InboundH2h, NetworkError, MAX_SCAN_RESULTS,
    SESSION_KIND_H2H, SESSION_KIND_ROUTED,
};
use routing_core::onboarding::{parse_discovery_from_manufacturer_data, CONSTELLATION_COMPANY_ID};
use routing_core::protocol::h2h::{H2hFrame, H2hPayload};
use routing_core::transport::TransportAddr;
use sha2::Digest as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;

use super::constants::{L2CAP_PSM_CHAR_UUID, ONBOARDING_SERVICE_UUID};

const CORE_BLUETOOTH_ADDR_LEN: u8 = 16;
const L2CAP_FRAME_BUF_SIZE: usize = 512;

pub fn transport_addr_for_device_id(device_id: &DeviceId) -> TransportAddr {
    let mut addr = [0u8; 16];
    if let Ok(uuid) = uuid::Uuid::parse_str(device_id.as_str()) {
        addr.copy_from_slice(uuid.as_bytes());
        TransportAddr::opaque(0, CORE_BLUETOOTH_ADDR_LEN, addr)
    } else {
        let digest = sha2::Sha256::digest(device_id.as_str().as_bytes());
        addr.copy_from_slice(&digest[..16]);
        TransportAddr::opaque(0, CORE_BLUETOOTH_ADDR_LEN, addr)
    }
}

pub struct AcceptedSession {
    pub device_id: DeviceId,
    pub transport_addr: TransportAddr,
    pub channel: L2capChannel,
    pub initial_payload: Vec<u8>,
}

pub struct MacInitiator {
    central: Arc<Central>,
    known_devices: Arc<Mutex<HashMap<TransportAddr, DeviceId>>>,
    pending: Option<(DeviceId, L2capChannel)>,
}

impl MacInitiator {
    pub fn new(central: Arc<Central>) -> Self {
        Self {
            central,
            known_devices: Arc::new(Mutex::new(HashMap::new())),
            pending: None,
        }
    }

    pub fn known_devices(&self) -> Arc<Mutex<HashMap<TransportAddr, DeviceId>>> {
        Arc::clone(&self.known_devices)
    }

    pub async fn send_routed_packet(
        &self,
        peer_transport_addr: TransportAddr,
        packet: &[u8],
    ) -> Result<(), NetworkError> {
        let device_id = self
            .known_devices
            .lock()
            .unwrap()
            .get(&peer_transport_addr)
            .cloned()
            .ok_or(NetworkError::ConnectionFailed)?;

        self.central
            .connect(&device_id)
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;
        self.central
            .discover_services(&device_id)
            .await
            .map_err(|_| NetworkError::ProtocolError)?;

        let psm_bytes = self
            .central
            .read_characteristic(&device_id, L2CAP_PSM_CHAR_UUID)
            .await
            .map_err(|_| NetworkError::ProtocolError)?;
        if psm_bytes.len() < 2 {
            let _ = self.central.disconnect(&device_id).await;
            return Err(NetworkError::ProtocolError);
        }

        let psm = Psm(u16::from_le_bytes([psm_bytes[0], psm_bytes[1]]));
        let mut channel = self
            .central
            .open_l2cap_channel(&device_id, psm)
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;

        let mut tx_buf = [0u8; L2CAP_FRAME_BUF_SIZE];
        if packet.len() + 1 > tx_buf.len() {
            let _ = channel.close().await;
            let _ = self.central.disconnect(&device_id).await;
            return Err(NetworkError::ProtocolError);
        }
        tx_buf[0] = SESSION_KIND_ROUTED;
        tx_buf[1..1 + packet.len()].copy_from_slice(packet);
        channel
            .write_all(&tx_buf[..1 + packet.len()])
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;

        let _ = channel.close().await;
        let _ = self.central.disconnect(&device_id).await;
        Ok(())
    }
}

impl H2hInitiator for MacInitiator {
    async fn scan(&mut self, duration_ms: u64) -> heapless::Vec<DiscoveryEvent, MAX_SCAN_RESULTS> {
        let mut out = heapless::Vec::new();

        // Scan without service filter. CoreBluetooth's
        // scanForPeripheralsWithServices: is unreliable for 128-bit UUIDs
        // that appear in scan response data. We filter manually after
        // collecting results.
        if self
            .central
            .start_scan(blew::central::ScanFilter {
                services: vec![],
                ..Default::default()
            })
            .await
            .is_err()
        {
            return out;
        }

        tokio::time::sleep(std::time::Duration::from_millis(duration_ms)).await;
        let devices = match self.central.discovered_devices().await {
            Ok(devices) => devices,
            Err(_) => {
                let _ = self.central.stop_scan().await;
                return out;
            }
        };
        let _ = self.central.stop_scan().await;
        log::info!("BLE scan found {} raw devices", devices.len());

        for device in devices.iter() {
            let has_service = device
                .services
                .iter()
                .any(|uuid| *uuid == ONBOARDING_SERVICE_UUID);
            let has_constellation_mfr = device
                .manufacturer_data
                .as_ref()
                .map(|d| {
                    d.len() >= 2 && u16::from_le_bytes([d[0], d[1]]) == CONSTELLATION_COMPANY_ID
                })
                .unwrap_or(false);
            if !has_service && !has_constellation_mfr {
                continue;
            }

            let transport_addr = transport_addr_for_device_id(&device.id);
            self.known_devices
                .lock()
                .unwrap()
                .insert(transport_addr, device.id.clone());

            if let Some(info) = device
                .manufacturer_data
                .as_ref()
                .and_then(|data| parse_discovery_from_manufacturer_data(data))
            {
                let _ = out.push(DiscoveryEvent {
                    short_addr: info.short_addr,
                    capabilities: info.capabilities,
                    network_addr: info.network_addr,
                    transport_addr,
                });
            }
        }

        // Discovery remains cheap because we parse manufacturer data directly
        // from scan results rather than serially connecting to each device.
        // GATT inspection still enriches diagnostics, but shared routing state
        // should start from the shared discovery payload path.
        out
    }

    async fn initiate_h2h(
        &mut self,
        peer_transport_addr: TransportAddr,
        our_payload: &H2hPayload,
    ) -> Result<H2hPayload, NetworkError> {
        let device_id = self
            .known_devices
            .lock()
            .unwrap()
            .get(&peer_transport_addr)
            .cloned()
            .ok_or(NetworkError::ConnectionFailed)?;

        self.central
            .connect(&device_id)
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;
        self.central
            .discover_services(&device_id)
            .await
            .map_err(|_| NetworkError::ProtocolError)?;

        let psm_bytes = self
            .central
            .read_characteristic(&device_id, L2CAP_PSM_CHAR_UUID)
            .await
            .map_err(|_| NetworkError::ProtocolError)?;
        if psm_bytes.len() < 2 {
            return Err(NetworkError::ProtocolError);
        }

        let psm = Psm(u16::from_le_bytes([psm_bytes[0], psm_bytes[1]]));
        let mut channel = self
            .central
            .open_l2cap_channel(&device_id, psm)
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;

        let mut tx_buf = [0u8; L2CAP_FRAME_BUF_SIZE];
        tx_buf[0] = SESSION_KIND_H2H;
        let tx_len = our_payload
            .serialize(&mut tx_buf[1..])
            .map_err(|_| NetworkError::ProtocolError)?;
        channel
            .write_all(&tx_buf[..tx_len + 1])
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;

        let mut rx_buf = [0u8; L2CAP_FRAME_BUF_SIZE];
        let rx_len = channel
            .read(&mut rx_buf)
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;
        if rx_len < 2 || rx_buf[0] != SESSION_KIND_H2H {
            return Err(NetworkError::ProtocolError);
        }
        let peer_payload =
            H2hPayload::deserialize(&rx_buf[1..rx_len]).map_err(|_| NetworkError::ProtocolError)?;

        self.pending = Some((device_id, channel));
        Ok(peer_payload)
    }

    async fn send_h2h_frame(&mut self, frame: &H2hFrame) -> Result<(), NetworkError> {
        let (_, channel) = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;
        let mut buf = [0u8; L2CAP_FRAME_BUF_SIZE];
        let len = frame
            .serialize(&mut buf)
            .map_err(|_| NetworkError::ProtocolError)?;
        channel
            .write_all(&buf[..len])
            .await
            .map_err(|_| NetworkError::ConnectionFailed)
    }

    async fn receive_h2h_frame(&mut self) -> Result<H2hFrame, NetworkError> {
        let (_, channel) = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;
        let mut buf = [0u8; L2CAP_FRAME_BUF_SIZE];
        let len = channel
            .read(&mut buf)
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;
        H2hFrame::deserialize(&buf[..len]).map_err(|_| NetworkError::ProtocolError)
    }

    async fn finish_h2h_session(&mut self) -> Result<(), NetworkError> {
        if let Some((device_id, mut channel)) = self.pending.take() {
            let _ = channel.close().await;
            let _ = self.central.disconnect(&device_id).await;
        }
        Ok(())
    }
}

pub struct MacResponder {
    inbound_rx: mpsc::Receiver<AcceptedSession>,
    pending: Option<AcceptedSession>,
}

impl MacResponder {
    pub fn new(inbound_rx: mpsc::Receiver<AcceptedSession>) -> Self {
        Self {
            inbound_rx,
            pending: None,
        }
    }
}

impl H2hResponder for MacResponder {
    async fn receive_h2h(&mut self) -> Result<InboundH2h, NetworkError> {
        let mut session = self
            .inbound_rx
            .recv()
            .await
            .ok_or(NetworkError::ConnectionFailed)?;

        let initial = if session.initial_payload.is_empty() {
            let mut buf = [0u8; L2CAP_FRAME_BUF_SIZE];
            let len = session
                .channel
                .read(&mut buf)
                .await
                .map_err(|_| NetworkError::ConnectionFailed)?;
            buf[..len].to_vec()
        } else {
            core::mem::take(&mut session.initial_payload)
        };
        if initial.len() < 2 || initial[0] != SESSION_KIND_H2H {
            return Err(NetworkError::ProtocolError);
        }
        let peer_payload =
            H2hPayload::deserialize(&initial[1..]).map_err(|_| NetworkError::ProtocolError)?;

        let inbound = InboundH2h {
            peer_transport_addr: session.transport_addr,
            peer_payload,
        };
        self.pending = Some(session);
        Ok(inbound)
    }

    async fn send_h2h_response(&mut self, payload: &H2hPayload) -> Result<(), NetworkError> {
        let session = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;
        let mut buf = [0u8; L2CAP_FRAME_BUF_SIZE];
        let len = payload
            .serialize(&mut buf)
            .map_err(|_| NetworkError::ProtocolError)?;
        session
            .channel
            .write_all(&buf[..len])
            .await
            .map_err(|_| NetworkError::ConnectionFailed)
    }

    async fn send_h2h_frame(&mut self, frame: &H2hFrame) -> Result<(), NetworkError> {
        let session = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;
        let mut buf = [0u8; L2CAP_FRAME_BUF_SIZE];
        let len = frame
            .serialize(&mut buf)
            .map_err(|_| NetworkError::ProtocolError)?;
        session
            .channel
            .write_all(&buf[..len])
            .await
            .map_err(|_| NetworkError::ConnectionFailed)
    }

    async fn receive_h2h_frame(&mut self) -> Result<H2hFrame, NetworkError> {
        let session = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;
        let mut buf = [0u8; L2CAP_FRAME_BUF_SIZE];
        let len = session
            .channel
            .read(&mut buf)
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;
        H2hFrame::deserialize(&buf[..len]).map_err(|_| NetworkError::ProtocolError)
    }

    async fn finish_h2h_session(&mut self) -> Result<(), NetworkError> {
        if let Some(mut session) = self.pending.take() {
            let _ = session.channel.close().await;
        }
        Ok(())
    }
}
