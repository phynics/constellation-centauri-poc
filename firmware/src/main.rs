// =============================================================================
// Constellation Mesh Node — BLE Firmware for ESP32
// =============================================================================
//
// ARCHITECTURE OVERVIEW
// ---------------------
// Four tasks run concurrently via `join4`:
//
//   1. ble_runner_task        — Pumps the HCI event loop + scan handler
//   2. run_responder_loop     — Connectable advertising + accept H2H (generic)
//   3. run_initiator_loop     — Discovery scan + initiate H2H (generic)
//   4. run_heartbeat_loop     — Tick uptime counter every 5 seconds (generic)
//
// The protocol logic (routing table updates, H2H scheduling) lives in
// `routing-core::behavior`. This file only contains ESP32/BLE plumbing.
// =============================================================================

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;

esp_bootloader_esp_idf::esp_app_desc!();

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use embassy_executor::Spawner;
use embassy_futures::join::join4;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Instant, Timer};

use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeCreateConn, LeSetScanEnable,
    LeSetScanParams,
};
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};

use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_hal::system::software_reset;
use esp_println::println;
use esp_radio::ble::controller::BleConnector;
use esp_storage::FlashStorage;

use static_cell::StaticCell;

use trouble_host::prelude::*;

pub mod node;
pub mod transport;

use routing_core::behavior::{
    apply_discovery_events, build_h2h_payload, collect_h2h_peer_snapshots, run_heartbeat_loop,
};
use routing_core::config::H2H_PSM;
use routing_core::crypto::encryption::CryptoError;
use routing_core::crypto::identity::{short_addr_of, NodeIdentity};
use routing_core::message::{route_message, MessageDecision, RoutedMessage};
use routing_core::network::{H2hInitiator, H2hResponder};
use routing_core::node::roles::Capabilities;
use routing_core::protocol::app::{
    EncryptedAppFrame, InfraFrame, InfraKind, PingPayload, PongPayload, APP_CONTENT_TYPE_UTF8,
};
use routing_core::protocol::h2h::H2hFrame;
use routing_core::protocol::packet::{
    build_packet_with_message_id, PacketHeader, PACKET_TYPE_FRAME_APP, PACKET_TYPE_FRAME_INFRA,
};
use routing_core::routing::table::RoutingTable;

use node::storage::ProvisioningState;
use transport::ble_network::{
    parse_discovery_from_adv, BleInitiator, BleResponder, DiscoveryInfo, InboundBleSession,
};

// =============================================================================
// Constants
// =============================================================================

const HEAP_SIZE: usize = 72 * 1024;
const CONNECTIONS_MAX: usize = 2;
const L2CAP_CHANNELS_MAX: usize = 4;

pub const CONSTELLATION_COMPANY_ID: u16 = 0x1234;

// =============================================================================
// Shared static state
// =============================================================================

static ROUTING_TABLE: StaticCell<Mutex<NoopRawMutex, RoutingTable>> = StaticCell::new();
static HEARTBEAT_UPTIME: StaticCell<Mutex<NoopRawMutex, u32>> = StaticCell::new();
static FLASH_MUTEX: StaticCell<Mutex<NoopRawMutex, FlashStorage<'static>>> = StaticCell::new();
static PROVISIONING_STATE: StaticCell<Mutex<NoopRawMutex, ProvisioningState>> = StaticCell::new();
static ROUTED_FORWARD_QUEUE: StaticCell<Channel<NoopRawMutex, RoutedForward, 8>> =
    StaticCell::new();

/// Scan handler delivers discovered peers into this channel.
static DISCOVERY_RX: StaticCell<Channel<NoopRawMutex, (BdAddr, AddrKind, DiscoveryInfo), 4>> =
    StaticCell::new();

#[derive(Clone, Copy)]
struct RoutedForward {
    peer_transport_addr: routing_core::transport::TransportAddr,
    len: usize,
    packet: [u8; 512],
}

// =============================================================================
// Entry point
// =============================================================================

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    esp_alloc::heap_allocator! {
        size: HEAP_SIZE
    }

    println!("Constellation Mesh Node - H2H (Heart2Heart)");
    println!("=============================================");
    println!("Build: {}", env!("BUILD_FINGERPRINT"));

    let peripherals = esp_hal::init(esp_hal::Config::default());

    println!("Initializing RTOS scheduler...");
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);

    #[cfg(target_arch = "riscv32")]
    let software_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);

    esp_rtos::start(
        timg0.timer0,
        #[cfg(target_arch = "riscv32")]
        software_interrupt.software_interrupt0,
    );

    println!("Initializing RNG (non-cryptographic - PoC only)...");
    let mut rng = Rng::new();
    let mut flash = FlashStorage::new(peripherals.FLASH);

    let identity = load_or_generate_identity(&mut flash, &mut rng);
    let mut provisioning_state = match node::storage::load_provisioning(&mut flash) {
        Ok(state) => {
            if let Some(committed) = state.committed {
                let certificate = committed.certificate_for(&identity);
                println!("Network authority: {:02x?}", &committed.network_pubkey[..8]);
                println!(
                    "Committed network pubkey: {:02x?}",
                    committed.network_pubkey
                );
                println!(
                    "Committed cert capabilities: 0x{:04x}",
                    committed.cert_capabilities
                );
                println!(
                    "Committed cert signature: {:02x?}",
                    &committed.cert_signature[..8]
                );
                println!(
                    "Committed membership verifies: {}",
                    certificate.verify_against_network(&committed.network_pubkey)
                );
            } else {
                println!("Onboarding state: ready");
            }
            state
        }
        Err(e) => {
            println!("Onboarding state unreadable: {:?}", e);
            ProvisioningState::default()
        }
    };

    let default_capabilities = Capabilities(Capabilities::ROUTE | Capabilities::APPLICATION).0;
    let effective_capabilities = node::storage::effective_capabilities(
        &identity,
        &mut provisioning_state,
        default_capabilities,
    );
    if provisioning_state.committed.is_none() && effective_capabilities == default_capabilities {
        println!("Using default capabilities");
    }
    println!("Node identity: {:02x?}", identity.short_addr());
    println!("Public key:    {:02x?}", identity.pubkey());

    println!("Initializing BLE controller...");
    let bluetooth = peripherals.BT;
    let connector =
        BleConnector::new(bluetooth, Default::default()).expect("Failed to create BLE connector");
    let controller: ExternalController<_, 20> = ExternalController::new(connector);

    let mut resources: HostResources<_, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();

    let address = derive_ble_address(&identity);
    println!("BLE address: {:02x?}", address);

    let stack = Box::leak(Box::new(
        trouble_host::new(controller, &mut resources)
            .set_random_address(address)
            // H2H now spans the initial sync exchange and any delayed-delivery
            // follow-up frames, so the CoC SPSM must be registered explicitly on
            // the stack builder using the current trouble-host API.
            .register_l2cap_spsm(H2H_PSM)
            .build(),
    ));
    let peripheral = stack.peripheral();
    let central = stack.central();
    let runner = stack.runner();

    // Shared state
    let routing_table = RoutingTable::new(*identity.short_addr());
    let routing_table = ROUTING_TABLE.init(Mutex::new(routing_table));
    let uptime = HEARTBEAT_UPTIME.init(Mutex::new(0u32));
    let discovery_rx = DISCOVERY_RX.init(Channel::new());
    let routed_forward_queue = ROUTED_FORWARD_QUEUE.init(Channel::new());
    let flash = FLASH_MUTEX.init(Mutex::new(flash));
    let provisioning_state = PROVISIONING_STATE.init(Mutex::new(provisioning_state));

    let scan_handler = ConstellationScanHandler {
        our_addr: address,
        discovery_rx,
    };

    let capabilities = Capabilities(effective_capabilities);

    let mut ble_responder = BleResponder::new(
        peripheral,
        &stack,
        &identity,
        capabilities.0,
        provisioning_state,
        flash,
    );

    let mut ble_initiator = BleInitiator::new(central, &stack, address, discovery_rx);

    println!("Ready — advertising for discovery + H2H exchange");

    let _ = join4(
        ble_runner_task(runner, &scan_handler),
        run_responder_loop_with_app_messages(
            &mut ble_responder,
            &identity,
            capabilities.0,
            routing_table,
            uptime,
            routed_forward_queue,
        ),
        run_initiator_loop_with_routed_forwarding(
            &mut ble_initiator,
            &identity,
            capabilities.0,
            routing_table,
            uptime,
            routed_forward_queue,
        ),
        run_heartbeat_loop(uptime, routing_table),
    )
    .await;
}

pub fn reboot_after_enrollment_commit() -> ! {
    software_reset()
}

async fn run_responder_loop_with_app_messages<C>(
    responder: &mut BleResponder<'_, C>,
    identity: &NodeIdentity,
    capabilities: u16,
    routing_table: &Mutex<NoopRawMutex, RoutingTable>,
    uptime: &Mutex<NoopRawMutex, u32>,
    routed_forward_queue: &Channel<NoopRawMutex, RoutedForward, 8>,
) -> !
where
    C: Controller,
{
    let addr_bytes = identity.short_addr();
    let jitter_ms = u16::from_le_bytes([addr_bytes[0], addr_bytes[1]]) % 2048;
    Timer::after(Duration::from_millis(jitter_ms as u64)).await;

    loop {
        match responder.receive_session().await {
            Ok(InboundBleSession::H2h(inbound)) => {
                let partner_short = match inbound.peer_payload.full_pubkey {
                    Some(pk) => short_addr_of(&pk),
                    None => {
                        let table = routing_table.lock().await;
                        table
                            .peers
                            .iter()
                            .find(|p| p.transport_addr == inbound.peer_transport_addr)
                            .map(|p| p.short_addr)
                            .unwrap_or([0u8; 8])
                    }
                };

                let response = build_h2h_payload(
                    identity,
                    capabilities,
                    uptime,
                    routing_table,
                    &partner_short,
                )
                .await;

                {
                    let mut table = routing_table.lock().await;
                    table.update_peer_from_h2h(
                        &inbound.peer_payload,
                        partner_short,
                        inbound.peer_transport_addr,
                        Instant::now().as_ticks(),
                    );
                    log::info!("[periph] H2H done, peers={}", table.peers.len());
                }

                if let Err(e) = responder.send_h2h_response(&response).await {
                    log::warn!("[periph] send_h2h_response error: {:?}", e);
                    let _ = responder.finish_h2h_session().await;
                    continue;
                }

                loop {
                    match responder.receive_h2h_frame().await {
                        Ok(H2hFrame::SessionDone) => break,
                        Ok(_) => {}
                        Err(e) => {
                            log::warn!("[periph] app frame rx error: {:?}", e);
                            break;
                        }
                    }
                }

                let _ = responder.finish_h2h_session().await;
            }
            Ok(InboundBleSession::Routed {
                peer_transport_addr,
                payload,
            }) => {
                handle_routed_packet(
                    identity,
                    capabilities,
                    routing_table,
                    peer_transport_addr,
                    payload.as_slice(),
                    routed_forward_queue,
                )
                .await;
            }
            Err(e) => {
                log::warn!("[periph] receive session error: {:?}", e);
            }
        }
    }
}

async fn handle_routed_packet(
    identity: &NodeIdentity,
    capabilities: u16,
    routing_table: &Mutex<NoopRawMutex, RoutingTable>,
    peer_transport_addr: routing_core::transport::TransportAddr,
    packet: &[u8],
    routed_forward_queue: &Channel<NoopRawMutex, RoutedForward, 8>,
) {
    let Ok((header, payload)) = PacketHeader::deserialize(packet) else {
        log::warn!("[routed] invalid packet header");
        return;
    };
    let sender_pubkey = {
        let table = routing_table.lock().await;
        table
            .peers
            .iter()
            .find(|p| p.transport_addr == peer_transport_addr || p.short_addr == header.src)
            .map(|p| p.pubkey)
    };
    if let Some(sender_pubkey) = sender_pubkey {
        if !header.verify(&sender_pubkey, payload) {
            log::warn!(
                "[routed] signature verify failed from {:02x?}",
                &header.src[..4]
            );
            return;
        }
    }

    let destination_is_low_power = {
        let table = routing_table.lock().await;
        table
            .find_peer(&header.dst)
            .map(|peer| Capabilities::is_low_power_endpoint_bits(peer.capabilities))
            .unwrap_or(false)
    };

    match {
        let mut table = routing_table.lock().await;
        route_message(
            &mut table,
            capabilities,
            destination_is_low_power,
            *identity.short_addr(),
            &RoutedMessage {
                destination: header.dst,
                is_broadcast: header.flags & routing_core::protocol::packet::FLAG_BROADCAST != 0,
                message_id: header.message_id,
                ttl: header.ttl,
                hop_count: header.hop_count,
            },
        )
    } {
        MessageDecision::DeliveredLocal => {}
        MessageDecision::Forward(plan) => {
            if let Some((_, next_hop_transport)) = plan.candidates.first() {
                let mut forwarded = [0u8; 512];
                if packet.len() <= forwarded.len() {
                    forwarded[..packet.len()].copy_from_slice(packet);
                    if let Ok((mut fwd_header, fwd_payload)) =
                        PacketHeader::deserialize(&forwarded[..packet.len()])
                    {
                        let forwarded_len = routing_core::config::HEADER_SIZE + fwd_payload.len();
                        fwd_header.ttl = fwd_header.ttl.saturating_sub(1);
                        fwd_header.hop_count = fwd_header.hop_count.saturating_add(1);
                        if fwd_header.serialize(&mut forwarded).is_ok() {
                            let _ = routed_forward_queue.try_send(RoutedForward {
                                peer_transport_addr: *next_hop_transport,
                                len: forwarded_len,
                                packet: forwarded,
                            });
                            log::info!(
                                "[routed] forwarding {:02x?} -> {:02x?} ttl={} hop={}",
                                &header.src[..4],
                                &header.dst[..4],
                                fwd_header.ttl,
                                fwd_header.hop_count
                            );
                            return;
                        }
                    }
                }
            }
            log::warn!(
                "[routed] failed to enqueue forward to {:02x?}",
                &header.dst[..4]
            );
            return;
        }
        MessageDecision::TtlExpired => {
            log::warn!("[routed] ttl expired for {:02x?}", &header.dst[..4]);
            return;
        }
        MessageDecision::Duplicate => {
            log::info!("[routed] duplicate msg_id={:02x?}", header.message_id);
            return;
        }
        MessageDecision::NoRoute { .. } => {
            log::warn!("[routed] no route to {:02x?}", &header.dst[..4]);
            return;
        }
    }

    match header.packet_type {
        PACKET_TYPE_FRAME_INFRA => match InfraFrame::deserialize(payload) {
            Ok(frame) => match frame.kind {
                InfraKind::Ping => {
                    if let Ok(ping) = PingPayload::deserialize(frame.payload.as_slice()) {
                        log::info!(
                            "[infra] ping from {:02x?} req={:02x?}",
                            &header.src[..4],
                            ping.request_id
                        );
                        let next_hop = {
                            let table = routing_table.lock().await;
                            table.forwarding_candidates(&header.src).first().copied()
                        };
                        if let Some((_, next_hop_transport)) = next_hop {
                            let pong = PongPayload {
                                request_id: ping.request_id,
                                responder_addr: *identity.short_addr(),
                                received_ttl: header.ttl,
                            };
                            let mut pong_payload_buf = [0u8; 32];
                            if let Ok(pong_payload_len) = pong.serialize(&mut pong_payload_buf) {
                                let mut infra_payload = heapless::Vec::new();
                                if infra_payload
                                    .extend_from_slice(&pong_payload_buf[..pong_payload_len])
                                    .is_ok()
                                {
                                    let infra = InfraFrame {
                                        kind: InfraKind::Pong,
                                        payload: infra_payload,
                                    };
                                    let mut payload_buf = [0u8; 256];
                                    if let Ok(payload_len) = infra.serialize(&mut payload_buf) {
                                        let mut packet_buf = [0u8; 512];
                                        if let Ok(packet_len) = build_packet_with_message_id(
                                            identity,
                                            PACKET_TYPE_FRAME_INFRA,
                                            0,
                                            header.src,
                                            ping.request_id,
                                            &payload_buf[..payload_len],
                                            &mut packet_buf,
                                        ) {
                                            let _ = routed_forward_queue.try_send(RoutedForward {
                                                peer_transport_addr: next_hop_transport,
                                                len: packet_len,
                                                packet: packet_buf,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => log::info!(
                    "[infra] from {:02x?} kind={:?} bytes={}",
                    &header.src[..4],
                    frame.kind,
                    frame.payload.len()
                ),
            },
            Err(_) => log::warn!("[infra] failed to decode payload"),
        },
        PACKET_TYPE_FRAME_APP => {
            let Some(sender_pubkey) = sender_pubkey else {
                log::warn!("[app] missing sender pubkey for {:02x?}", &header.src[..4]);
                return;
            };
            match EncryptedAppFrame::deserialize(payload) {
                Ok(frame) => {
                    let mut plain = [0u8; 192];
                    match frame.decrypt_user_data(identity, &sender_pubkey, &mut plain) {
                        Ok((APP_CONTENT_TYPE_UTF8, len)) => {
                            let text = core::str::from_utf8(&plain[..len]).unwrap_or("<non-utf8>");
                            println!(
                                "[app] from {:02x?} msg_id={:02x?} body={}",
                                &header.src[..4],
                                header.message_id,
                                text
                            );
                        }
                        Ok((content_type, len)) => {
                            log::info!(
                                "[app] from {:02x?} content_type={} bytes={}",
                                &header.src[..4],
                                content_type,
                                len
                            );
                        }
                        Err(err) => {
                            log::warn!("[app] decrypt failed: {:?}", map_crypto_error(err));
                        }
                    }
                }
                Err(_) => log::warn!("[app] failed to decode encrypted payload"),
            }
        }
        other => log::info!("[routed] unsupported packet_type={}", other),
    }
}

fn map_crypto_error(err: routing_core::protocol::app::AppError) -> CryptoError {
    match err {
        routing_core::protocol::app::AppError::Crypto(inner) => inner,
        _ => CryptoError::DecryptionFailed,
    }
}

async fn run_initiator_loop_with_routed_forwarding<C>(
    initiator: &mut BleInitiator<'_, C>,
    identity: &NodeIdentity,
    capabilities: u16,
    routing_table: &Mutex<NoopRawMutex, RoutingTable>,
    uptime: &Mutex<NoopRawMutex, u32>,
    routed_forward_queue: &Channel<NoopRawMutex, RoutedForward, 8>,
) -> !
where
    C: Controller
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeSetScanEnable>
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdAsync<LeCreateConn>,
{
    Timer::after(Duration::from_secs(3)).await;

    loop {
        while let Ok(forward) = routed_forward_queue.try_receive() {
            let _ = initiator
                .send_routed_packet(forward.peer_transport_addr, &forward.packet[..forward.len])
                .await;
        }

        let cycle_start = Instant::now();
        let events = initiator.scan(7_000).await;
        apply_discovery_events(routing_table, &events).await;

        let our_addr = *identity.short_addr();
        let peer_snapshots =
            collect_h2h_peer_snapshots(identity, capabilities, routing_table).await;

        for (peer_addr, peer_transport_addr) in peer_snapshots.iter() {
            let offset = if Capabilities::is_low_power_endpoint_bits(capabilities) {
                0
            } else {
                routing_core::protocol::h2h::slot_offset(&our_addr, peer_addr)
            };
            let target_time = cycle_start + Duration::from_secs(offset);
            if Instant::now() < target_time {
                Timer::at(target_time).await;
            }

            let payload =
                build_h2h_payload(identity, capabilities, uptime, routing_table, peer_addr).await;
            match initiator.initiate_h2h(*peer_transport_addr, &payload).await {
                Ok(peer_payload) => {
                    let mut table = routing_table.lock().await;
                    table.update_peer_from_h2h(
                        &peer_payload,
                        *peer_addr,
                        *peer_transport_addr,
                        Instant::now().as_ticks(),
                    );
                    let _ = initiator.finish_h2h_session().await;
                    if Capabilities::is_low_power_endpoint_bits(capabilities) {
                        break;
                    }
                }
                Err(_) => {
                    let _ = initiator.finish_h2h_session().await;
                }
            }

            while let Ok(forward) = routed_forward_queue.try_receive() {
                let _ = initiator
                    .send_routed_packet(forward.peer_transport_addr, &forward.packet[..forward.len])
                    .await;
            }
        }

        let elapsed = Instant::now() - cycle_start;
        let cycle = Duration::from_secs(routing_core::config::H2H_CYCLE_SECS);
        if elapsed < cycle {
            Timer::after(cycle - elapsed).await;
        }
    }
}

// =============================================================================
// BLE scan event handler
// =============================================================================

struct ConstellationScanHandler {
    our_addr: Address,
    discovery_rx: &'static Channel<NoopRawMutex, (BdAddr, AddrKind, DiscoveryInfo), 4>,
}

impl EventHandler for ConstellationScanHandler {
    fn on_adv_reports(&self, mut it: LeAdvReportsIter<'_>) {
        while let Some(Ok(report)) = it.next() {
            if report.addr.raw() == self.our_addr.addr.raw() {
                continue;
            }
            if let Some(info) = parse_discovery_from_adv(report.data) {
                let _ = self
                    .discovery_rx
                    .try_send((report.addr, report.addr_kind, info));
            }
        }
    }
}

// =============================================================================
// BLE runner task
// =============================================================================

async fn ble_runner_task<C: Controller, E: EventHandler>(
    mut runner: Runner<'_, C, DefaultPacketPool>,
    handler: &E,
) {
    loop {
        if let Err(e) = runner.run_with_handler(handler).await {
            println!("[ble_runner] error: {:?}", e);
        }
    }
}

// =============================================================================
// Utility functions
// =============================================================================

fn load_or_generate_identity(flash: &mut FlashStorage, rng: &mut Rng) -> NodeIdentity {
    use node::storage;

    match storage::is_provisioned(flash) {
        Ok(true) => {
            println!("Loading identity from flash...");
            match storage::load_identity(flash) {
                Ok(id) => {
                    println!("Identity loaded successfully");
                    id
                }
                Err(e) => {
                    println!("Failed to load identity: {:?}", e);
                    println!("Generating new identity...");
                    let id = NodeIdentity::generate_insecure(rng);
                    if let Err(e) = storage::save_identity(flash, &id) {
                        println!("Warning: Failed to save identity: {:?}", e);
                    }
                    id
                }
            }
        }
        Ok(false) | Err(_) => {
            println!("No identity found. Generating new identity...");
            let id = NodeIdentity::generate_insecure(rng);
            match storage::save_identity(flash, &id) {
                Ok(_) => println!("Identity saved to flash"),
                Err(e) => println!("Warning: Failed to save identity: {:?}", e),
            }
            id
        }
    }
}

fn derive_ble_address(identity: &NodeIdentity) -> Address {
    let short_addr = identity.short_addr();
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&short_addr[0..6]);
    mac[5] |= 0xC0;
    Address::random(mac)
}
