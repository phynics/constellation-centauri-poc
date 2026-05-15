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
use trouble_host_macros::{gatt_server, gatt_service};

use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_time::with_timeout;

use routing_core::config::{H2H_CONNECTION_TIMEOUT_SECS, H2H_MTU, H2H_PSM};
use routing_core::crypto::identity::{network_addr_of, NodeIdentity, ShortAddr};
use routing_core::network::{
    DiscoveryEvent, H2hInitiator, H2hResponder, InboundH2h, NetworkError, MAX_SCAN_RESULTS,
    SESSION_KIND_H2H, SESSION_KIND_ROUTED,
};
use routing_core::onboarding::{
    CONSTELLATION_COMPANY_ID, CONSTELLATION_PROTOCOL_SIGNATURE, DISCOVERY_PAYLOAD_SIZE,
    ONBOARDING_READY_MARKER, ONBOARDING_READY_NETWORK_ADDR, NodeCertificate,
    deserialize_discovery, serialize_discovery,
};

pub use routing_core::onboarding::{DiscoveryInfo, parse_discovery_from_adv};
use routing_core::protocol::h2h::{H2hFrame, H2hPayload};
use routing_core::transport::TransportAddr;

use crate::node::storage::{self, ProvisioningState};
use crate::reboot_after_enrollment_commit;
use esp_storage::FlashStorage;

// ── Discovery payload ─────────────────────────────────────────────────────────

const PROTOCOL_SIGNATURE_LEN: usize = 32;
const NETWORK_MARKER_LEN: usize = 33;
const CERT_DATA_LEN: usize = NodeCertificate::CERT_DATA_SIZE;
const EMPTY_CAPABILITIES: [u8; 2] = [0u8; 2];
const EMPTY_PUBKEY: [u8; 32] = [0xFFu8; 32];
const EMPTY_SIGNATURE: [u8; 64] = [0xFFu8; 64];
/// 128-bit UUID for the onboarding service, in **BLE little-endian** wire order.
///
/// The UUID `43d7aa10-5f4b-4c84-a100-000000000001` in RFC 4122 big-endian is
/// `[43 d7 aa 10 5f 4b 4c 84 a1 00 00 00 00 00 00 01]`, but the BLE spec
/// (Core Spec Vol 3, Part B §2.5.1) requires 128-bit UUIDs in advertising
/// data to be transmitted in little-endian byte order. `trouble-host` writes
/// the raw bytes as-is, so we must provide the LE-reversed form here.
pub const ONBOARDING_SERVICE_UUID_BYTES: [u8; 16] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, 0x84, 0x4c, 0x4b, 0x5f, 0x10, 0xaa, 0xd7, 0x43,
];

#[gatt_server(connections_max = 1, mutex_type = NoopRawMutex, attribute_table_size = 80)]
pub struct OnboardingServer {
    onboarding: OnboardingService,
}

#[gatt_service(uuid = "43d7aa10-5f4b-4c84-a100-000000000001")]
pub struct OnboardingService {
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-000000000002", read, value = [0u8; PROTOCOL_SIGNATURE_LEN])]
    protocol_signature: [u8; PROTOCOL_SIGNATURE_LEN],
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-000000000003", read, value = [0u8; NETWORK_MARKER_LEN])]
    network_marker: [u8; NETWORK_MARKER_LEN],
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-000000000004", read, value = [0u8; 32])]
    node_pubkey: [u8; 32],
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-000000000005", read, value = [0u8; 2])]
    capabilities: [u8; 2],
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-000000000006", read, value = [0u8; 8])]
    short_addr: [u8; 8],
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-000000000007", read, value = [0u8; 2])]
    l2cap_psm: [u8; 2],
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-000000000008", read, write, value = [0xFFu8; 32])]
    authority_pubkey: [u8; 32],
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-000000000009", read, write, value = [0u8; 2])]
    cert_capabilities: [u8; 2],
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-00000000000a", read, write, value = [0xFFu8; 64])]
    cert_signature: [u8; 64],
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-00000000000b", write, value = [0u8; 1])]
    commit_enrollment: [u8; 1],
    #[characteristic(uuid = "43d7aa10-5f4b-4c84-a100-00000000000c", read, value = [0xFFu8; CERT_DATA_LEN])]
    cert_data: [u8; CERT_DATA_LEN],
}

fn init_onboarding_server(
    identity: &NodeIdentity,
    capabilities: u16,
    provisioning: &ProvisioningState,
) -> OnboardingServer<'static> {
    let server = OnboardingServer::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "Constellation",
        appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
    }))
    .expect("failed to create onboarding gatt server");

    let mut protocol_signature = [0u8; PROTOCOL_SIGNATURE_LEN];
    protocol_signature[..CONSTELLATION_PROTOCOL_SIGNATURE.len()]
        .copy_from_slice(CONSTELLATION_PROTOCOL_SIGNATURE);
    let _ = server.set(&server.onboarding.protocol_signature, &protocol_signature);

    apply_provisioning_to_server(&server, provisioning, identity, capabilities);
    server
}

fn apply_provisioning_to_server(
    server: &OnboardingServer<'static>,
    provisioning: &ProvisioningState,
    identity: &NodeIdentity,
    capabilities: u16,
) {
    let mut network_marker = [0u8; NETWORK_MARKER_LEN];
    let (authority_pubkey, cert_capabilities, cert_signature, cert_data) =
        if let Some(committed) = provisioning.committed {
            network_marker[..32].copy_from_slice(&committed.network_pubkey);
            let cert = NodeCertificate {
                pubkey: identity.pubkey(),
                capabilities: committed.cert_capabilities,
                network_signature: committed.cert_signature,
            };
            (
                committed.network_pubkey,
                committed.cert_capabilities.to_le_bytes(),
                committed.cert_signature,
                cert.to_cert_bytes(&committed.network_pubkey),
            )
        } else {
            network_marker[..ONBOARDING_READY_MARKER.len()].copy_from_slice(ONBOARDING_READY_MARKER);
            (
                provisioning.staged.authority_pubkey.unwrap_or(EMPTY_PUBKEY),
                provisioning
                    .staged
                    .cert_capabilities
                    .map(|caps| caps.to_le_bytes())
                    .unwrap_or(EMPTY_CAPABILITIES),
                provisioning
                    .staged
                    .cert_signature
                    .unwrap_or(EMPTY_SIGNATURE),
                [0xFFu8; CERT_DATA_LEN],
            )
        };

    let _ = server.set(&server.onboarding.network_marker, &network_marker);
    let _ = server.set(&server.onboarding.authority_pubkey, &authority_pubkey);
    let _ = server.set(&server.onboarding.cert_capabilities, &cert_capabilities);
    let _ = server.set(&server.onboarding.cert_signature, &cert_signature);
    let _ = server.set(&server.onboarding.cert_data, &cert_data);
    let _ = server.set(&server.onboarding.node_pubkey, &identity.pubkey());
    let _ = server.set(&server.onboarding.capabilities, &capabilities.to_le_bytes());
    let _ = server.set(&server.onboarding.short_addr, identity.short_addr());
    let _ = server.set(&server.onboarding.l2cap_psm, &H2H_PSM.to_le_bytes());
}

async fn handle_onboarding_gatt_event(
    server: &OnboardingServer<'static>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    identity: &NodeIdentity,
    provisioning_state: &Mutex<NoopRawMutex, ProvisioningState>,
    flash: &Mutex<NoopRawMutex, FlashStorage<'static>>,
) -> Result<bool, NetworkError> {
    match conn.next().await {
        GattConnectionEvent::Disconnected { .. } => Ok(false),
        GattConnectionEvent::Gatt {
            event: GattEvent::Write(event),
        } => {
            let handle = event.handle();
            let data = event.data();
            let mut provisioning = provisioning_state.lock().await;

            if let Err(err) =
                apply_onboarding_write(server, handle, data, identity, &mut provisioning)
            {
                drop(provisioning);
                event
                    .reject(err)
                    .map_err(|_| NetworkError::ProtocolError)?
                    .send()
                    .await;
                return Ok(true);
            }

            if handle == server.onboarding.commit_enrollment.handle {
                let mut flash = flash.lock().await;
                storage::save_provisioning(&mut *flash, identity, &provisioning)
                    .map_err(|_| NetworkError::ProtocolError)?;
            }

            let advertised_capabilities = if let Some(membership) = provisioning.committed {
                membership.cert_capabilities
            } else {
                u16::from_le_bytes(
                    conn.get(&server.onboarding.capabilities)
                        .map_err(|_| NetworkError::ProtocolError)?,
                )
            };
            apply_provisioning_to_server(server, &provisioning, identity, advertised_capabilities);
            drop(provisioning);
            event
                .accept()
                .map_err(|_| NetworkError::ProtocolError)?
                .send()
                .await;
            if handle == server.onboarding.commit_enrollment.handle {
                Timer::after(Duration::from_millis(100)).await;
                reboot_after_enrollment_commit();
            }
            Ok(true)
        }
        _ => Ok(true),
    }
}

fn apply_onboarding_write(
    server: &OnboardingServer<'static>,
    handle: u16,
    data: &[u8],
    identity: &NodeIdentity,
    provisioning: &mut ProvisioningState,
) -> Result<(), AttErrorCode> {
    if handle == server.onboarding.authority_pubkey.handle {
        if provisioning.committed.is_some() || data.len() != 32 {
            return Err(AttErrorCode::VALUE_NOT_ALLOWED);
        }
        let mut authority = [0u8; 32];
        authority.copy_from_slice(data);
        provisioning.staged.authority_pubkey = Some(authority);
        return Ok(());
    }

    if handle == server.onboarding.cert_capabilities.handle {
        if provisioning.committed.is_some() || data.len() != 2 {
            return Err(AttErrorCode::VALUE_NOT_ALLOWED);
        }
        provisioning.staged.cert_capabilities = Some(u16::from_le_bytes([data[0], data[1]]));
        return Ok(());
    }

    if handle == server.onboarding.cert_signature.handle {
        if provisioning.committed.is_some() || data.len() != 64 {
            return Err(AttErrorCode::VALUE_NOT_ALLOWED);
        }
        let mut cert_signature = [0u8; 64];
        cert_signature.copy_from_slice(data);
        provisioning.staged.cert_signature = Some(cert_signature);
        return Ok(());
    }

    if handle == server.onboarding.commit_enrollment.handle {
        return storage::commit_staged_enrollment(identity, provisioning)
            .map(|_| ())
            .map_err(|_| AttErrorCode::VALUE_NOT_ALLOWED);
    }

    Err(AttErrorCode::WRITE_NOT_PERMITTED)
}

// ── BleResponder ──────────────────────────────────────────────────────────────

/// Manages the peripheral / advertising side of H2H exchanges.
///
/// Holds the open `Connection` and `L2capChannel` between `receive_h2h` and
/// `send_h2h_response` so the BLE link stays alive across both calls.
pub struct BleResponder<'stack, C: Controller> {
    peripheral: Peripheral<'stack, C, DefaultPacketPool>,
    stack: &'stack Stack<'stack, C, DefaultPacketPool>,
    identity: &'stack NodeIdentity,
    identity_short: ShortAddr,
    capabilities: u16,
    server: OnboardingServer<'static>,
    provisioning_state: &'static Mutex<NoopRawMutex, ProvisioningState>,
    flash: &'static Mutex<NoopRawMutex, FlashStorage<'static>>,
    /// Open connection + channel from the last `receive_h2h` call.
    pending: Option<(
        Connection<'stack, DefaultPacketPool>,
        L2capChannel<'stack, DefaultPacketPool>,
    )>,
}

pub enum InboundBleSession {
    H2h(InboundH2h),
    Routed {
        peer_transport_addr: TransportAddr,
        payload: Vec<u8, 512>,
    },
}

impl<'stack, C: Controller> BleResponder<'stack, C> {
    pub fn new(
        peripheral: Peripheral<'stack, C, DefaultPacketPool>,
        stack: &'stack Stack<'stack, C, DefaultPacketPool>,
        identity: &'stack NodeIdentity,
        capabilities: u16,
        provisioning_state: &'static Mutex<NoopRawMutex, ProvisioningState>,
        flash: &'static Mutex<NoopRawMutex, FlashStorage<'static>>,
    ) -> Self {
        let provisioning = provisioning_state
            .try_lock()
            .expect("provisioning state unavailable during init");
        Self {
            peripheral,
            stack,
            identity,
            identity_short: *identity.short_addr(),
            capabilities,
            server: init_onboarding_server(identity, capabilities, &provisioning),
            provisioning_state,
            flash,
            pending: None,
        }
    }

    pub async fn receive_session(&mut self) -> Result<InboundBleSession, NetworkError> {
        'advertise: loop {
            // Compute network_addr from provisioning state
            let network_addr = {
                let provisioning = self.provisioning_state.lock().await;
                if let Some(committed) = provisioning.committed {
                    network_addr_of(&committed.network_pubkey)
                } else {
                    ONBOARDING_READY_NETWORK_ADDR
                }
            };

            let mut disc_buf = [0u8; DISCOVERY_PAYLOAD_SIZE];
            if serialize_discovery(
                &self.identity_short,
                self.capabilities,
                &network_addr,
                &mut disc_buf,
            )
            .is_none()
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
                Err(_) => {
                    Timer::after(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let mut scan_data = [0u8; 31];
            let scan_len = match AdStructure::encode_slice(
                &[AdStructure::CompleteServiceUuids128(&[
                    ONBOARDING_SERVICE_UUID_BYTES,
                ])],
                &mut scan_data[..],
            ) {
                Ok(len) => len,
                Err(_) => 0,
            };

            let advertiser = match self
                .peripheral
                .advertise(
                    &Default::default(),
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..adv_len],
                        scan_data: &scan_data[..scan_len],
                    },
                )
                .await
            {
                Ok(a) => a,
                Err(_) => {
                    Timer::after(Duration::from_secs(3)).await;
                    continue;
                }
            };

            let conn = match advertiser.accept().await {
                Ok(c) => c,
                Err(_) => continue,
            };
            let gatt_conn = match conn.with_attribute_server(&self.server) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let l2cap_config = L2capChannelConfig {
                mtu: Some(H2H_MTU),
                ..Default::default()
            };
            let listener = L2capChannel::listen(self.stack, gatt_conn.raw());
            let mut channel = loop {
                match select(
                    listener.accept(&l2cap_config),
                    handle_onboarding_gatt_event(
                        &self.server,
                        &gatt_conn,
                        self.identity,
                        self.provisioning_state,
                        self.flash,
                    ),
                )
                .await
                {
                    Either::First(result) => match result {
                        Ok(ch) => break ch,
                        Err(_) => continue 'advertise,
                    },
                    Either::Second(result) => match result {
                        Ok(true) => continue,
                        Ok(false) | Err(_) => continue 'advertise,
                    },
                }
            };

            let mut rx_buf = [0u8; 512];
            let rx_len = match channel.receive(self.stack, &mut rx_buf).await {
                Ok(n) => n,
                Err(_) => continue,
            };
            if rx_len < 2 {
                continue;
            }

            let mut peer_mac = [0u8; 6];
            peer_mac.copy_from_slice(gatt_conn.raw().peer_address().addr.raw());
            let peer_transport_addr = TransportAddr::ble(peer_mac);

            match rx_buf[0] {
                SESSION_KIND_H2H => {
                    let peer_payload = match H2hPayload::deserialize(&rx_buf[1..rx_len]) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let conn = gatt_conn.raw().clone();
                    drop(gatt_conn);
                    self.pending = Some((conn, channel));
                    return Ok(InboundBleSession::H2h(InboundH2h {
                        peer_transport_addr,
                        peer_payload,
                    }));
                }
                SESSION_KIND_ROUTED => {
                    let mut payload = Vec::new();
                    if payload.extend_from_slice(&rx_buf[1..rx_len]).is_err() {
                        continue;
                    }
                    drop(channel);
                    drop(gatt_conn);
                    return Ok(InboundBleSession::Routed {
                        peer_transport_addr,
                        payload,
                    });
                }
                _ => continue,
            }
        }
    }
}

impl<'stack, C: Controller> H2hResponder for BleResponder<'stack, C> {
    async fn receive_h2h(&mut self) -> Result<InboundH2h, NetworkError> {
        loop {
            match self.receive_session().await? {
                InboundBleSession::H2h(inbound) => return Ok(inbound),
                InboundBleSession::Routed { .. } => continue,
            }
        }
    }

    async fn send_h2h_response(&mut self, payload: &H2hPayload) -> Result<(), NetworkError> {
        let (_conn, channel) = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;

        let mut tx_buf = [0u8; 512];
        tx_buf[0] = SESSION_KIND_H2H;
        let tx_len = payload
            .serialize(&mut tx_buf[1..])
            .map_err(|_| NetworkError::ProtocolError)?;

        channel
            .send(self.stack, &tx_buf[..tx_len + 1])
            .await
            .map_err(|e| {
                log::warn!("[periph] L2CAP send error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        Ok(())
    }

    async fn send_h2h_frame(&mut self, frame: &H2hFrame) -> Result<(), NetworkError> {
        let (_conn, channel) = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;

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
        let (_conn, channel) = self.pending.as_mut().ok_or(NetworkError::ProtocolError)?;

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

    pub async fn send_routed_packet(
        &mut self,
        peer_transport_addr: TransportAddr,
        packet: &[u8],
    ) -> Result<(), NetworkError> {
        let peer_mac = peer_transport_addr
            .as_ble_mac()
            .ok_or(NetworkError::ProtocolError)?;
        let central = self
            .central
            .as_mut()
            .expect("BleInitiator: central missing during send_routed_packet");

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
            log::warn!("[central] Routed connect failed: {:?}", e);
            NetworkError::ConnectionFailed
        })?;

        let l2cap_config = L2capChannelConfig {
            mtu: Some(H2H_MTU),
            ..Default::default()
        };

        let mut channel = L2capChannel::create(self.stack, &conn, H2H_PSM, &l2cap_config)
            .await
            .map_err(|e| {
                log::warn!("[central] Routed L2CAP create error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        let mut tx_buf = [0u8; 512];
        if packet.len() + 1 > tx_buf.len() {
            return Err(NetworkError::ProtocolError);
        }
        tx_buf[0] = SESSION_KIND_ROUTED;
        tx_buf[1..1 + packet.len()].copy_from_slice(packet);

        channel
            .send(self.stack, &tx_buf[..1 + packet.len()])
            .await
            .map_err(|e| {
                log::warn!("[central] Routed send error: {:?}", e);
                NetworkError::ConnectionFailed
            })?;

        Ok(())
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
                                network_addr: info.network_addr,
                                transport_addr: TransportAddr::ble(mac),
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
        peer_transport_addr: TransportAddr,
        our_payload: &H2hPayload,
    ) -> Result<H2hPayload, NetworkError> {
        let peer_mac = peer_transport_addr
            .as_ble_mac()
            .ok_or(NetworkError::ProtocolError)?;
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
        tx_buf[0] = SESSION_KIND_H2H;
        let tx_len = our_payload
            .serialize(&mut tx_buf[1..])
            .map_err(|_| NetworkError::ProtocolError)?;

        channel
            .send(self.stack, &tx_buf[..tx_len + 1])
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
        if rx_len < 2 || rx_buf[0] != SESSION_KIND_H2H {
            return Err(NetworkError::ProtocolError);
        }

        let peer_payload =
            H2hPayload::deserialize(&rx_buf[1..rx_len]).map_err(|_| NetworkError::ProtocolError)?;

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
