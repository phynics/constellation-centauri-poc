#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use blew::l2cap::{L2capChannel, Psm};
use blew::{Central, DeviceId};
use routing_core::crypto::identity::short_addr_of;
use routing_core::network::{
    DiscoveryEvent, H2hInitiator, H2hResponder, InboundH2h, NetworkError, MAX_SCAN_RESULTS,
};
use routing_core::protocol::h2h::{H2hFrame, H2hPayload};
use routing_core::transport::TransportAddr;
use sha2::Digest as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;

use super::constants::{
    CAPABILITIES_CHAR_UUID, L2CAP_PSM_CHAR_UUID, NODE_PUBKEY_CHAR_UUID, ONBOARDING_SERVICE_UUID,
};

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
}

impl H2hInitiator for MacInitiator {
    async fn scan(&mut self, duration_ms: u64) -> heapless::Vec<DiscoveryEvent, MAX_SCAN_RESULTS> {
        let mut out = heapless::Vec::new();

        if self
            .central
            .start_scan(blew::central::ScanFilter {
                services: vec![ONBOARDING_SERVICE_UUID],
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

        for device in devices.into_iter() {
            if !device
                .services
                .iter()
                .any(|uuid| *uuid == ONBOARDING_SERVICE_UUID)
            {
                continue;
            }

            let transport_addr = transport_addr_for_device_id(&device.id);
            self.known_devices
                .lock()
                .unwrap()
                .insert(transport_addr, device.id.clone());

            if self.central.connect(&device.id).await.is_err() {
                continue;
            }
            let _ = self.central.discover_services(&device.id).await;

            let pubkey = self
                .central
                .read_characteristic(&device.id, NODE_PUBKEY_CHAR_UUID)
                .await;
            let capabilities = self
                .central
                .read_characteristic(&device.id, CAPABILITIES_CHAR_UUID)
                .await;

            let _ = self.central.disconnect(&device.id).await;

            let (Ok(pubkey), Ok(capabilities)) = (pubkey, capabilities) else {
                continue;
            };
            if pubkey.len() != 32 || capabilities.len() != 2 {
                continue;
            }

            let mut pubkey_arr = [0u8; 32];
            pubkey_arr.copy_from_slice(&pubkey);
            let _ = out.push(DiscoveryEvent {
                short_addr: short_addr_of(&pubkey_arr),
                capabilities: u16::from_le_bytes([capabilities[0], capabilities[1]]),
                transport_addr,
            });
        }

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
        let tx_len = our_payload
            .serialize(&mut tx_buf)
            .map_err(|_| NetworkError::ProtocolError)?;
        channel
            .write_all(&tx_buf[..tx_len])
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;

        let mut rx_buf = [0u8; L2CAP_FRAME_BUF_SIZE];
        let rx_len = channel
            .read(&mut rx_buf)
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;
        let peer_payload =
            H2hPayload::deserialize(&rx_buf[..rx_len]).map_err(|_| NetworkError::ProtocolError)?;

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

        let mut buf = [0u8; L2CAP_FRAME_BUF_SIZE];
        let len = session
            .channel
            .read(&mut buf)
            .await
            .map_err(|_| NetworkError::ConnectionFailed)?;
        let peer_payload =
            H2hPayload::deserialize(&buf[..len]).map_err(|_| NetworkError::ProtocolError)?;

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
