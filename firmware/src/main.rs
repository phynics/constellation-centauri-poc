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

use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_hal::system::software_reset;
use esp_println::println;
use esp_radio::ble::controller::BleConnector;
use esp_storage::FlashStorage;

use static_cell::StaticCell;

use trouble_host::prelude::*;

use esp_bootloader_esp_idf::partitions::read_partition_table;

pub mod node;
pub mod transport;

use routing_core::behavior::{
    apply_discovery_events, build_h2h_payload, collect_h2h_peer_snapshots,
    drain_responder_h2h_frames_until_done, respond_to_inbound_h2h_sync, run_heartbeat_loop,
    run_initiator_loop_with_observer, InboundH2hSyncError, InitiatorCycleObserver,
};
use routing_core::config::H2H_PSM;
use routing_core::crypto::encryption::CryptoError;
use routing_core::crypto::identity::NodeIdentity;
use routing_core::facade::{
    observe_routed_receive_outcome, DeliveredInfra, MeshFacade, RoutedReceiveObserver, RoutedTxPlan,
};
use routing_core::network::{H2hInitiator, H2hResponder};
use routing_core::node::roles::Capabilities;
use routing_core::protocol::h2h::H2hFrame;
use routing_core::routing::table::RoutingTable;

use node::partitioned_flash::PartitionedFlash;
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

// =============================================================================
// Shared static state
// =============================================================================

static ROUTING_TABLE: StaticCell<Mutex<NoopRawMutex, RoutingTable>> = StaticCell::new();
static HEARTBEAT_UPTIME: StaticCell<Mutex<NoopRawMutex, u32>> = StaticCell::new();
static FLASH_MUTEX: StaticCell<Mutex<NoopRawMutex, PartitionedFlash<FlashStorage<'static>>>> =
    StaticCell::new();
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

    // Set up logger that forwards to esp_println
    struct EspLogger;
    impl log::Log for EspLogger {
        fn enabled(&self, _metadata: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            println!(
                "[{}][{}] {}",
                record.target(),
                record.level(),
                record.args()
            );
        }
        fn flush(&self) {}
    }
    static LOGGER: EspLogger = EspLogger;
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info);

    println!("Initializing RNG (non-cryptographic - PoC only)...");
    let mut rng = Rng::new();
    let mut raw_flash = FlashStorage::new(peripherals.FLASH);

    // Look up the `constellation` data partition to find its base offset.
    let constellation_base = {
        let mut pt_buf = [0u8; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN];
        match read_partition_table(&mut raw_flash, &mut pt_buf) {
            Ok(pt) => {
                let mut found: Option<u32> = None;
                for entry in pt.iter() {
                    if entry.label_as_str() == "constellation" {
                        found = Some(entry.offset());
                        break;
                    }
                }
                match found {
                    Some(offset) => {
                        println!("Constellation partition at 0x{:x}", offset);
                        offset
                    }
                    None => {
                        println!("Warning: no `constellation` partition, falling back to offset 0");
                        0
                    }
                }
            }
            Err(e) => {
                println!(
                    "Warning: failed to read partition table ({:?}), falling back to offset 0",
                    e
                );
                0
            }
        }
    };

    let mut flash = PartitionedFlash {
        inner: raw_flash,
        base: constellation_base,
    };

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
                println!("Onboarding state: uninitialized");
            }
            state
        }
        Err(node::storage::StorageError::InvalidMagic) => {
            println!("Onboarding state: uninitialized");
            ProvisioningState::default()
        }
        Err(node::storage::StorageError::InvalidVersion) => {
            println!("Onboarding state: unsupported legacy record, using defaults");
            ProvisioningState::default()
        }
        Err(e) => {
            println!("Onboarding state unreadable: {:?}; using defaults", e);
            ProvisioningState::default()
        }
    };

    let default_capabilities = Capabilities(Capabilities::ROUTE | Capabilities::APPLICATION).0;
    let effective_capabilities = node::storage::effective_capabilities(
        &identity,
        &mut provisioning_state,
        default_capabilities,
    );

    // Log onboarding state summary
    let network_addr = provisioning_state
        .committed
        .as_ref()
        .map(|c| routing_core::crypto::identity::network_addr_of(&c.network_pubkey))
        .unwrap_or(routing_core::onboarding::ONBOARDING_READY_NETWORK_ADDR);
    if provisioning_state.committed.is_some() {
        println!(
            "Onboarding: ENROLLED (network_addr = {:02x?})",
            network_addr
        );
    } else {
        println!("Onboarding: READY (advertising for enrollment)");
    }
    println!("Capabilities: 0x{:04x} ({})", effective_capabilities, {
        let caps = Capabilities(effective_capabilities);
        let mut parts = alloc::vec::Vec::new();
        if caps.contains(Capabilities::ROUTE) {
            parts.push("ROUTE");
        }
        if caps.contains(Capabilities::STORE) {
            parts.push("STORE");
        }
        if caps.contains(Capabilities::APPLICATION) {
            parts.push("APP");
        }
        if caps.contains(Capabilities::BRIDGE) {
            parts.push("BRIDGE");
        }
        if caps.contains(Capabilities::LOW_ENERGY) {
            parts.push("LE");
        }
        if caps.contains(Capabilities::MOBILE) {
            parts.push("MOBILE");
        }
        alloc::format!("{}", parts.join(" | "))
    });

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
                match respond_to_inbound_h2h_sync(
                    responder,
                    &inbound,
                    identity,
                    capabilities,
                    uptime,
                    routing_table,
                )
                .await
                {
                    Ok(_) => {
                        let table = routing_table.lock().await;
                        log::info!("[periph] H2H done, peers={}", table.peers.len());
                    }
                    Err(InboundH2hSyncError::UnresolvedPartner) => {
                        log::warn!(
                            "[periph] cannot resolve partner identity for transport {:?}; skipping session",
                            inbound.peer_transport_addr
                        );
                        let _ = responder.finish_h2h_session().await;
                        continue;
                    }
                    Err(InboundH2hSyncError::SendResponse(e)) => {
                        log::warn!("[periph] send_h2h_response error: {:?}", e);
                        let _ = responder.finish_h2h_session().await;
                        continue;
                    }
                }

                drain_responder_h2h_frames_until_done(responder).await;

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
    struct FirmwareRoutedObserver<'a> {
        routed_forward_queue: &'a Channel<NoopRawMutex, RoutedForward, 8>,
    }

    impl RoutedReceiveObserver for FirmwareRoutedObserver<'_> {
        fn on_invalid_packet(&mut self) {
            log::warn!("[routed] invalid packet header");
        }

        fn on_signature_failed(&mut self, source: [u8; 8]) {
            log::warn!(
                "[routed] signature verify failed from {:02x?}",
                &source[..4]
            );
        }

        fn on_forward(
            &mut self,
            source: [u8; 8],
            destination: [u8; 8],
            ttl: u8,
            hop_count: u8,
            plan: RoutedTxPlan,
        ) {
            let _ = self.routed_forward_queue.try_send(RoutedForward {
                peer_transport_addr: plan.next_hop_transport,
                len: plan.len,
                packet: plan.packet,
            });
            log::info!(
                "[routed] forwarding {:02x?} -> {:02x?} ttl={} hop={}",
                &source[..4],
                &destination[..4],
                ttl,
                hop_count
            );
        }

        fn on_ttl_expired(&mut self, destination: [u8; 8]) {
            log::warn!("[routed] ttl expired for {:02x?}", &destination[..4]);
        }

        fn on_duplicate(&mut self, message_id: [u8; 8]) {
            log::info!("[routed] duplicate msg_id={:02x?}", message_id);
        }

        fn on_no_route(
            &mut self,
            destination: [u8; 8],
            _observe_broadcast: bool,
            _should_retain_for_lpn: bool,
        ) {
            log::warn!("[routed] no route to {:02x?}", &destination[..4]);
        }

        fn on_delivered_infra(&mut self, infra: DeliveredInfra) {
            match infra {
                DeliveredInfra::Ping {
                    source,
                    payload,
                    pong,
                } => {
                    log::info!(
                        "[infra] ping from {:02x?} req={:02x?}",
                        &source[..4],
                        payload.request_id
                    );
                    if let Some(pong) = pong {
                        let _ = self.routed_forward_queue.try_send(RoutedForward {
                            peer_transport_addr: pong.next_hop_transport,
                            len: pong.len,
                            packet: pong.packet,
                        });
                    }
                }
                DeliveredInfra::Other {
                    source,
                    kind,
                    payload_len,
                } => {
                    log::info!(
                        "[infra] from {:02x?} kind={:?} bytes={}",
                        &source[..4],
                        kind,
                        payload_len
                    );
                }
                DeliveredInfra::Pong { source, payload } => {
                    log::info!(
                        "[infra] pong from {:02x?} req={:02x?} recv_ttl={}",
                        &source[..4],
                        payload.request_id,
                        payload.received_ttl
                    );
                }
            }
        }

        fn on_delivered_app_utf8(&mut self, app: routing_core::facade::DeliveredUtf8App) {
            let text = core::str::from_utf8(&app.plaintext[..app.len]).unwrap_or("<non-utf8>");
            println!(
                "[app] from {:02x?} msg_id={:02x?} body={}",
                &app.source[..4],
                app.message_id,
                text
            );
        }

        fn on_unsupported_local_app(&mut self, source: [u8; 8], content_type: u8, len: usize) {
            log::info!(
                "[app] from {:02x?} content_type={} bytes={}",
                &source[..4],
                content_type,
                len
            );
        }

        fn on_decrypt_failed(
            &mut self,
            _source: [u8; 8],
            error: routing_core::protocol::app::AppError,
        ) {
            log::warn!("[app] decrypt failed: {:?}", map_crypto_error(error));
        }

        fn on_missing_sender_pubkey(&mut self, source: [u8; 8]) {
            log::warn!("[app] missing sender pubkey for {:02x?}", &source[..4]);
        }

        fn on_unsupported_local_packet(&mut self, _source: [u8; 8], packet_type: u8) {
            log::info!("[routed] unsupported packet_type={}", packet_type);
        }

        fn on_invalid_local_payload(&mut self, _source: [u8; 8], packet_type: u8) {
            log::warn!(
                "[routed] failed to decode local payload for packet_type={}",
                packet_type
            );
        }
    }

    let outcome = {
        let mut table = routing_table.lock().await;
        let mut mesh = MeshFacade::new(&mut table, identity, capabilities);
        mesh.receive(peer_transport_addr, packet)
    };
    let mut observer = FirmwareRoutedObserver {
        routed_forward_queue,
    };
    observe_routed_receive_outcome(outcome, &mut observer);
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
    struct FirmwareInitiatorObserver<'a> {
        routed_forward_queue: &'a Channel<NoopRawMutex, RoutedForward, 8>,
    }

    impl<'a, C> InitiatorCycleObserver<BleInitiator<'a, C>> for FirmwareInitiatorObserver<'a>
    where
        C: Controller
            + ControllerCmdSync<LeSetScanParams>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeCreateConn>,
    {
        async fn before_cycle(&mut self, initiator: &mut BleInitiator<'a, C>) {
            while let Ok(forward) = self.routed_forward_queue.try_receive() {
                let _ = initiator
                    .send_routed_packet(forward.peer_transport_addr, &forward.packet[..forward.len])
                    .await;
            }
        }

        async fn after_peer(&mut self, initiator: &mut BleInitiator<'a, C>) {
            while let Ok(forward) = self.routed_forward_queue.try_receive() {
                let _ = initiator
                    .send_routed_packet(forward.peer_transport_addr, &forward.packet[..forward.len])
                    .await;
            }
        }
    }

    let mut observer = FirmwareInitiatorObserver {
        routed_forward_queue,
    };
    run_initiator_loop_with_observer(
        initiator,
        identity,
        capabilities,
        routing_table,
        uptime,
        &mut observer,
    )
    .await
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

fn load_or_generate_identity<S: NorFlash + ReadNorFlash>(
    flash: &mut S,
    rng: &mut Rng,
) -> NodeIdentity {
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
        Ok(false) => {
            println!("No identity found. Generating new identity...");
            let id = NodeIdentity::generate_insecure(rng);
            match storage::save_identity(flash, &id) {
                Ok(_) => println!("Identity saved to flash"),
                Err(e) => println!("Warning: Failed to save identity: {:?}", e),
            }
            id
        }
        Err(e) => {
            println!("Identity storage unreadable: {:?}", e);
            println!("Generating new identity...");
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
