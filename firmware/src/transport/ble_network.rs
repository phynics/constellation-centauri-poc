//! BLE implementations of `H2hResponder` and `H2hInitiator`.
//!
//! `BleResponder` wraps the trouble-host `Peripheral` and holds the open
//! L2CAP channel between `receive_h2h` and `send_h2h_response`.
//!
//! `BleInitiator` wraps trouble-host `Central` + a scan handler channel.
//! During `scan()` it creates a `Scanner`, drains the discovery channel for
//! the given duration, then hands `Central` back via `into_inner()`.

use embassy_time::{Duration, Instant, Timer};
use heapless::Vec;

use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeCreateConn, LeSetScanEnable,
    LeSetScanParams,
};
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use trouble_host::prelude::*;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::with_timeout;

use routing_core::config::{H2H_CONNECTION_TIMEOUT_SECS, H2H_MTU, H2H_PSM};
use routing_core::crypto::identity::ShortAddr;
use routing_core::network::{
    DiscoveryEvent, H2hInitiator, H2hResponder, InboundH2h, NetworkError, MAX_SCAN_RESULTS,
};
use routing_core::protocol::h2h::{H2hFrame, H2hPayload};

use crate::CONSTELLATION_COMPANY_ID;

// ── Discovery payload ─────────────────────────────────────────────────────────

pub const DISCOVERY_PAYLOAD_SIZE: usize = 10;

/// Lightweight advertisement payload: [short_addr: 8][capabilities: 2]
pub struct DiscoveryInfo {
    pub short_addr: ShortAddr,
    pub capabilities: u16,
}

pub fn serialize_discovery(
    short_addr: &ShortAddr,
    capabilities: u16,
    buf: &mut [u8],
) -> Option<usize> {
    if buf.len() < DISCOVERY_PAYLOAD_SIZE {
        return None;
    }
    buf[0..8].copy_from_slice(short_addr);
    buf[8..10].copy_from_slice(&capabilities.to_le_bytes());
    Some(DISCOVERY_PAYLOAD_SIZE)
}

pub fn deserialize_discovery(data: &[u8]) -> Option<DiscoveryInfo> {
    if data.len() < DISCOVERY_PAYLOAD_SIZE {
        return None;
    }
    let mut short_addr = [0u8; 8];
    short_addr.copy_from_slice(&data[0..8]);
    let capabilities = u16::from_le_bytes([data[8], data[9]]);
    Some(DiscoveryInfo {
        short_addr,
        capabilities,
    })
}

pub fn parse_discovery_from_adv(data: &[u8]) -> Option<DiscoveryInfo> {
    let mut i = 0;
    while i + 1 < data.len() {
        let len = data[i] as usize;
        if len == 0 || i + 1 + len > data.len() {
            break;
        }
        let ad_type = data[i + 1];
        if ad_type == 0xFF && len >= 3 {
            let company_id = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            if company_id == CONSTELLATION_COMPANY_ID {
                let payload_start = i + 4;
                let payload_end = i + 1 + len;
                if payload_start < payload_end {
                    return deserialize_discovery(&data[payload_start..payload_end]);
                }
            }
        }
        i += 1 + len;
    }
    None
}

// ── BleResponder ──────────────────────────────────────────────────────────────

/// Manages the peripheral / advertising side of H2H exchanges.
///
/// Holds the open `Connection` and `L2capChannel` between `receive_h2h` and
/// `send_h2h_response` so the BLE link stays alive across both calls.
pub struct BleResponder<'stack, C: Controller> {
    peripheral: Peripheral<'stack, C, DefaultPacketPool>,
    stack: &'stack Stack<'stack, C, DefaultPacketPool>,
    identity_short: ShortAddr,
    capabilities: u16,
    /// Open connection + channel from the last `receive_h2h` call.
    pending: Option<(
        Connection<'stack, DefaultPacketPool>,
        L2capChannel<'stack, DefaultPacketPool>,
    )>,
}

impl<'stack, C: Controller> BleResponder<'stack, C> {
    pub fn new(
        peripheral: Peripheral<'stack, C, DefaultPacketPool>,
        stack: &'stack Stack<'stack, C, DefaultPacketPool>,
        identity_short: ShortAddr,
        capabilities: u16,
    ) -> Self {
        Self {
            peripheral,
            stack,
            identity_short,
            capabilities,
            pending: None,
        }
    }
}

impl<'stack, C: Controller> H2hResponder for BleResponder<'stack, C> {
    async fn receive_h2h(&mut self) -> Result<InboundH2h, NetworkError> {
        // Drop any stale pending state from a previous (failed) exchange.
        self.pending = None;

        loop {
            // Build advertisement
            let mut disc_buf = [0u8; DISCOVERY_PAYLOAD_SIZE];
            if serialize_discovery(&self.identity_short, self.capabilities, &mut disc_buf).is_none()
            {
                Timer::after(Duration::from_secs(1)).await;
                continue;
            }

            let mut adv_data = [0u8; 31];
            let adv_len = match AdStructure::encode_slice(
                &[
                    AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                    AdStructure::ManufacturerSpecificData {
                        company_identifier: CONSTELLATION_COMPANY_ID,
                        payload: &disc_buf,
                    },
                ],
                &mut adv_data[..],
            ) {
                Ok(len) => len,
                Err(e) => {
                    log::warn!("[periph] AD encode error: {:?}", e);
                    Timer::after(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let advertiser = match self
                .peripheral
                .advertise(
                    &Default::default(),
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..adv_len],
                        scan_data: &[],
                    },
                )
                .await
            {
                Ok(a) => a,
                Err(e) => {
                    log::warn!("[periph] Advertise error: {:?}", e);
                    Timer::after(Duration::from_secs(3)).await;
                    continue;
                }
            };

            let conn = match advertiser.accept().await {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("[periph] Accept error: {:?}", e);
                    continue;
                }
            };

            log::debug!(
                "[periph] Connection from {:02x?}",
                conn.peer_address().addr.raw()
            );

            let l2cap_config = L2capChannelConfig {
                mtu: Some(H2H_MTU),
                ..Default::default()
            };

            // trouble-host now models inbound CoC setup as a pending listener on
            // the already-accepted BLE connection. Accepting here keeps the
            // channel open across the whole H2H session, including delayed-
            // delivery follow-up frames added above the base peer-sync exchange.
            let mut channel =
                match L2capChannel::listen(self.stack, &conn).accept(&l2cap_config).await {
                    Ok(ch) => ch,
                    Err(e) => {
                        log::warn!("[periph] L2CAP accept error: {:?}", e);
                        continue;
                    }
                };

            // Receive peer's payload
            let mut rx_buf = [0u8; 512];
            let rx_len = match channel.receive(self.stack, &mut rx_buf).await {
                Ok(n) => n,
                Err(e) => {
                    log::warn!("[periph] L2CAP rx error: {:?}", e);
                    continue;
                }
            };

            let peer_payload = match H2hPayload::deserialize(&rx_buf[..rx_len]) {
                Ok(p) => p,
                Err(_) => {
                    log::warn!("[periph] H2H deserialize FAILED ({} bytes)", rx_len);
                    continue;
                }
            };

            let mut peer_mac = [0u8; 6];
            peer_mac.copy_from_slice(conn.peer_address().addr.raw());

            // Store connection + channel for send_h2h_response
            self.pending = Some((conn, channel));

            return Ok(InboundH2h {
                peer_mac,
                peer_payload,
            });
        }
    }

    async fn send_h2h_response(&mut self, payload: &H2hPayload) -> Result<(), NetworkError> {
        let (conn, channel) = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;
        let _ = conn; // keep conn alive while we use channel

        let mut tx_buf = [0u8; 512];
        let tx_len = payload
            .serialize(&mut tx_buf)
            .map_err(|_| NetworkError::ProtocolError)?;

        channel
            .send(self.stack, &tx_buf[..tx_len])
            .await
            .map_err(|e| {
                log::warn!("[periph] L2CAP send error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        Ok(())
    }

    async fn send_h2h_frame(&mut self, frame: &H2hFrame) -> Result<(), NetworkError> {
        let (conn, channel) = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;
        let _ = conn;

        let mut tx_buf = [0u8; 512];
        let tx_len = frame
            .serialize(&mut tx_buf)
            .map_err(|_| NetworkError::ProtocolError)?;

        channel
            .send(self.stack, &tx_buf[..tx_len])
            .await
            .map_err(|e| {
                log::warn!("[periph] L2CAP frame send error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        Ok(())
    }

    async fn receive_h2h_frame(&mut self) -> Result<H2hFrame, NetworkError> {
        let (conn, channel) = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;
        let _ = conn;

        let mut rx_buf = [0u8; 512];
        let rx_len = channel
            .receive(self.stack, &mut rx_buf)
            .await
            .map_err(|e| {
                log::warn!("[periph] L2CAP frame rx error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        H2hFrame::deserialize(&rx_buf[..rx_len]).map_err(|_| NetworkError::ProtocolError)
    }

    async fn finish_h2h_session(&mut self) -> Result<(), NetworkError> {
        // Brief flush delay before dropping the connection.
        Timer::after(Duration::from_millis(200)).await;
        self.pending = None;
        Ok(())
    }
}

// ── BleInitiator ──────────────────────────────────────────────────────────────

/// Manages the central / scanning side of H2H exchanges.
pub struct BleInitiator<'stack, C>
where
    C: Controller
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeSetScanEnable>
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdAsync<LeCreateConn>,
{
    /// `None` only while a `Scanner` is active during `scan()`.
    central: Option<Central<'stack, C, DefaultPacketPool>>,
    stack: &'stack Stack<'stack, C, DefaultPacketPool>,
    our_addr: Address,
    discovery_rx: &'static Channel<NoopRawMutex, (BdAddr, AddrKind, DiscoveryInfo), 4>,
    pending: Option<(
        Connection<'stack, DefaultPacketPool>,
        L2capChannel<'stack, DefaultPacketPool>,
    )>,
}

impl<'stack, C> BleInitiator<'stack, C>
where
    C: Controller
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeSetScanEnable>
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdAsync<LeCreateConn>,
{
    pub fn new(
        central: Central<'stack, C, DefaultPacketPool>,
        stack: &'stack Stack<'stack, C, DefaultPacketPool>,
        our_addr: Address,
        discovery_rx: &'static Channel<NoopRawMutex, (BdAddr, AddrKind, DiscoveryInfo), 4>,
    ) -> Self {
        Self {
            central: Some(central),
            stack,
            our_addr,
            discovery_rx,
            pending: None,
        }
    }
}

impl<'stack, C> H2hInitiator for BleInitiator<'stack, C>
where
    C: Controller
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeSetScanEnable>
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdAsync<LeCreateConn>,
{
    async fn scan(&mut self, duration_ms: u64) -> Vec<DiscoveryEvent, MAX_SCAN_RESULTS> {
        let mut results = Vec::new();
        let central = self.central.take().expect("BleInitiator: central missing");
        let mut scanner = Scanner::new(central);

        let scan_config = ScanConfig {
            active: false,
            phys: PhySet::M1,
            interval: Duration::from_millis(100),
            window: Duration::from_millis(100),
            ..Default::default()
        };

        match scanner.scan(&scan_config).await {
            Ok(_session) => {
                let deadline = Instant::now() + Duration::from_millis(duration_ms);
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining == Duration::from_ticks(0) {
                        break;
                    }
                    match with_timeout(remaining, self.discovery_rx.receive()).await {
                        Ok((bd_addr, _addr_kind, info)) => {
                            // Skip our own advertisements
                            if bd_addr.raw() == self.our_addr.addr.raw() {
                                continue;
                            }
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(bd_addr.raw());
                            let _ = results.push(DiscoveryEvent {
                                short_addr: info.short_addr,
                                capabilities: info.capabilities,
                                mac,
                            });
                        }
                        Err(_timeout) => break,
                    }
                }
            }
            Err(e) => {
                log::warn!("[central] Scan error: {:?}", e);
            }
        }

        self.central = Some(scanner.into_inner());
        results
    }

    async fn initiate_h2h(
        &mut self,
        peer_mac: [u8; 6],
        our_payload: &H2hPayload,
    ) -> Result<H2hPayload, NetworkError> {
        let central = self
            .central
            .as_mut()
            .expect("BleInitiator: central missing during initiate_h2h");

        let target = Address::random(peer_mac);
        let connect_config = ConnectConfig {
            scan_config: ScanConfig {
                filter_accept_list: &[target],
                timeout: Duration::from_secs(H2H_CONNECTION_TIMEOUT_SECS),
                ..Default::default()
            },
            connect_params: Default::default(),
        };

        let conn = central.connect(&connect_config).await.map_err(|e| {
            log::warn!("[central] Connect failed: {:?}", e);
            NetworkError::ConnectionFailed
        })?;

        let l2cap_config = L2capChannelConfig {
            mtu: Some(H2H_MTU),
            ..Default::default()
        };

        let mut channel = L2capChannel::create(self.stack, &conn, H2H_PSM, &l2cap_config)
            .await
            .map_err(|e| {
                log::warn!("[central] L2CAP create error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        // Initiator sends first
        let mut tx_buf = [0u8; 512];
        let tx_len = our_payload
            .serialize(&mut tx_buf)
            .map_err(|_| NetworkError::ProtocolError)?;

        channel
            .send(self.stack, &tx_buf[..tx_len])
            .await
            .map_err(|e| {
                log::warn!("[central] L2CAP send error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        // Receive peer's payload
        let mut rx_buf = [0u8; 512];
        let rx_len = channel
            .receive(self.stack, &mut rx_buf)
            .await
            .map_err(|e| {
                log::warn!("[central] L2CAP rx error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        let peer_payload =
            H2hPayload::deserialize(&rx_buf[..rx_len]).map_err(|_| NetworkError::ProtocolError)?;

        // Keep the session alive so higher layers can exchange delayed-delivery
        // control/data frames before explicitly closing the connection.
        self.pending = Some((conn, channel));
        Ok(peer_payload)
    }

    async fn send_h2h_frame(&mut self, frame: &H2hFrame) -> Result<(), NetworkError> {
        let (conn, channel) = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;
        let _ = conn;

        let mut tx_buf = [0u8; 512];
        let tx_len = frame
            .serialize(&mut tx_buf)
            .map_err(|_| NetworkError::ProtocolError)?;

        channel
            .send(self.stack, &tx_buf[..tx_len])
            .await
            .map_err(|e| {
                log::warn!("[central] L2CAP frame send error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        Ok(())
    }

    async fn receive_h2h_frame(&mut self) -> Result<H2hFrame, NetworkError> {
        let (conn, channel) = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;
        let _ = conn;

        let mut rx_buf = [0u8; 512];
        let rx_len = channel
            .receive(self.stack, &mut rx_buf)
            .await
            .map_err(|e| {
                log::warn!("[central] L2CAP frame rx error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        H2hFrame::deserialize(&rx_buf[..rx_len]).map_err(|_| NetworkError::ProtocolError)
    }

    async fn finish_h2h_session(&mut self) -> Result<(), NetworkError> {
        self.pending = None;
        Ok(())
    }
}
