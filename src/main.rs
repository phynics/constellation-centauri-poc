// =============================================================================
// Constellation Mesh Node — BLE Firmware for ESP32
// =============================================================================
//
// ARCHITECTURE OVERVIEW
// ---------------------
// Nodes discover each other via lightweight BLE advertisements, then exchange
// full heartbeat data through direct H2H (Heart2Heart) L2CAP connections.
//
//   peripheral_h2h_task: Advertises as connectable for discovery. When a peer
//                        connects, accepts an L2CAP channel and exchanges H2H
//                        payloads (respond side).
//
//   central_h2h_task:    Discovers new peers via scanning, then initiates H2H
//                        connections to known peers on a scheduled cycle.
//                        Deterministic pair hashing decides who initiates and
//                        the time slot within each 60 s cycle.
//
// H2H payloads carry the full pubkey, capabilities, uptime, and a list of the
// node's top N known peers — replacing Bloom filters on the wire.
//
// CONCURRENCY MODEL
// -----------------
// Four tasks run concurrently via `join4`:
//
//   1. ble_runner_task        — Pumps the HCI event loop + scan handler
//   2. peripheral_h2h_task    — Connectable advertising + accept H2H
//   3. central_h2h_task       — Discovery scan + initiate H2H
//   4. heartbeat_update_task  — Tick uptime counter every 5 seconds
// =============================================================================

#![no_std]
#![no_main]

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

use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_println::println;
use esp_radio::ble::controller::BleConnector;
use esp_storage::FlashStorage;

use static_cell::StaticCell;

use trouble_host::prelude::*;

use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList,
    LeClearFilterAcceptList,
    LeCreateConn,
    LeSetScanEnable,
    LeSetScanParams,
};
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};

pub mod config;
pub mod crypto;
pub mod node;
pub mod protocol;
pub mod routing;
pub mod transport;

use config::{H2H_CYCLE_SECS, H2H_CONNECTION_TIMEOUT_SECS, H2H_MTU, H2H_PSM};
use crypto::identity::{NodeIdentity, ShortAddr, short_addr_of};
use node::roles::Capabilities;
use protocol::h2h::{self, H2hPayload};
use routing::table::{RoutingTable, TransportAddr};

// =============================================================================
// Constants
// =============================================================================

const HEAP_SIZE: usize = 72 * 1024;
const CONNECTIONS_MAX: usize = 2;
const L2CAP_CHANNELS_MAX: usize = 4; // signal + att + 2 CoC
const CONSTELLATION_COMPANY_ID: u16 = 0x1234;

/// Discovery advertisement payload: [short_addr: 8][capabilities: 2] = 10 bytes
const DISCOVERY_PAYLOAD_SIZE: usize = 10;

// =============================================================================
// Discovery payload (lightweight, for advertisements only)
// =============================================================================

struct DiscoveryInfo {
    short_addr: ShortAddr,
    capabilities: u16,
}

fn serialize_discovery(identity: &NodeIdentity, capabilities: u16, buf: &mut [u8]) -> Option<usize> {
    if buf.len() < DISCOVERY_PAYLOAD_SIZE {
        return None;
    }
    buf[0..8].copy_from_slice(identity.short_addr());
    buf[8..10].copy_from_slice(&capabilities.to_le_bytes());
    Some(DISCOVERY_PAYLOAD_SIZE)
}

fn deserialize_discovery(data: &[u8]) -> Option<DiscoveryInfo> {
    if data.len() < DISCOVERY_PAYLOAD_SIZE {
        return None;
    }
    let mut short_addr = [0u8; 8];
    short_addr.copy_from_slice(&data[0..8]);
    let capabilities = u16::from_le_bytes([data[8], data[9]]);
    Some(DiscoveryInfo { short_addr, capabilities })
}

// =============================================================================
// Shared static state
// =============================================================================

static ROUTING_TABLE: StaticCell<Mutex<NoopRawMutex, RoutingTable>> = StaticCell::new();
static HEARTBEAT_UPTIME: StaticCell<Mutex<NoopRawMutex, u32>> = StaticCell::new();

/// Channel for the scan handler to pass discovered peers to the central task.
static DISCOVERY_RX: StaticCell<Channel<NoopRawMutex, (BdAddr, AddrKind, DiscoveryInfo), 4>> =
    StaticCell::new();

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
    println!("Node identity: {:02x?}", identity.short_addr());
    println!("Public key:    {:02x?}", identity.pubkey());

    println!("Initializing BLE controller...");
    let bluetooth = peripherals.BT;
    let connector = BleConnector::new(bluetooth, Default::default())
        .expect("Failed to create BLE connector");
    let controller: ExternalController<_, 20> = ExternalController::new(connector);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();

    let address = derive_ble_address(&identity);
    println!("BLE address: {:02x?}", address);

    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);

    let Host {
        mut peripheral,
        central,
        runner,
        ..
    } = stack.build();

    // Shared state
    let routing_table = RoutingTable::new(*identity.short_addr());
    let routing_table = ROUTING_TABLE.init(Mutex::new(routing_table));
    let uptime = HEARTBEAT_UPTIME.init(Mutex::new(0u32));
    let discovery_rx = DISCOVERY_RX.init(Channel::new());

    let scan_handler = ConstellationScanHandler {
        our_addr: address,
        discovery_rx,
    };

    let capabilities = Capabilities(Capabilities::ROUTE | Capabilities::APPLICATION);

    println!("Ready — advertising for discovery + H2H exchange");

    let _ = join4(
        ble_runner_task(runner, &scan_handler),
        peripheral_h2h_task(
            &mut peripheral,
            &stack,
            &identity,
            capabilities.0,
            uptime,
            routing_table,
        ),
        central_h2h_task(
            central,
            &stack,
            &identity,
            capabilities.0,
            uptime,
            discovery_rx,
            routing_table,
        ),
        heartbeat_update_task(uptime, routing_table),
    )
    .await;
}

// =============================================================================
// Helpers
// =============================================================================

/// Build an H2H payload from local state, tailored for a specific partner.
///
/// - Omits our pubkey if the partner already has it (their entry has pubkey != [0;32]).
/// - Uses recency-weighted sampling filtered to exclude peers the partner already knows.
async fn build_h2h_payload(
    identity: &NodeIdentity,
    capabilities: u16,
    uptime: &Mutex<NoopRawMutex, u32>,
    routing_table: &Mutex<NoopRawMutex, RoutingTable>,
    partner_addr: &ShortAddr,
    now_ticks: u64,
) -> H2hPayload {
    let uptime_secs = *uptime.lock().await;

    let (peers, peer_count, include_pubkey) = {
        let table = routing_table.lock().await;

        // Check if partner already has our pubkey
        let partner_knows_us = table.find_peer(partner_addr)
            .map(|e| e.pubkey != [0u8; 32])
            .unwrap_or(false);

        // Derive a simple seed from our addr XOR'd with ticks
        let addr_bytes = identity.short_addr();
        let addr_u32 = u32::from_le_bytes([addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]]);
        let seed = addr_u32 ^ (now_ticks as u32);

        let (peers, count) = table.top_peers_for(partner_addr, now_ticks, seed);
        (peers, count, !partner_knows_us)
    };

    H2hPayload {
        full_pubkey: if include_pubkey { Some(identity.pubkey()) } else { None },
        capabilities,
        uptime_secs,
        peers,
        peer_count,
    }
}

// =============================================================================
// BLE advertising data parser
// =============================================================================

fn parse_discovery_from_adv(data: &[u8]) -> Option<DiscoveryInfo> {
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

// =============================================================================
// Scan event handler (discovery only)
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
                let _ = self.discovery_rx.try_send((report.addr, report.addr_kind, info));
            }
        }
    }
}

// =============================================================================
// Task 1: BLE runner
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
// Task 2: Peripheral H2H — connectable advertising + accept incoming H2H
// =============================================================================

async fn peripheral_h2h_task<'a, C: Controller>(
    peripheral: &mut Peripheral<'a, C, DefaultPacketPool>,
    stack: &'a Stack<'a, C, DefaultPacketPool>,
    identity: &NodeIdentity,
    capabilities: u16,
    uptime: &'static Mutex<NoopRawMutex, u32>,
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
) {
    // Per-node startup jitter
    let jitter_ms =
        u16::from_le_bytes([identity.short_addr()[0], identity.short_addr()[1]]) % 2048;
    println!("[periph] Startup jitter: {}ms", jitter_ms);
    Timer::after(Duration::from_millis(jitter_ms as u64)).await;

    loop {
        // Build discovery advertisement
        let mut disc_buf = [0u8; DISCOVERY_PAYLOAD_SIZE];
        if serialize_discovery(identity, capabilities, &mut disc_buf).is_none() {
            Timer::after(Duration::from_secs(3)).await;
            continue;
        }

        let mut adv_data = [0u8; 31];
        let len = match AdStructure::encode_slice(
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
                println!("[periph] AD encode error: {:?}", e);
                Timer::after(Duration::from_secs(3)).await;
                continue;
            }
        };

        // Advertise as connectable
        match peripheral
            .advertise(
                &Default::default(),
                Advertisement::ConnectableScannableUndirected {
                    adv_data: &adv_data[..len],
                    scan_data: &[],
                },
            )
            .await
        {
            Ok(advertiser) => {
                // Wait for an incoming connection
                match advertiser.accept().await {
                    Ok(conn) => {
                        println!(
                            "[periph] Connection from {:02x?}",
                            conn.peer_address().raw()
                        );

                        // Accept L2CAP channel from the initiator
                        let l2cap_config = L2capChannelConfig {
                            mtu: Some(H2H_MTU),
                            ..Default::default()
                        };

                        match L2capChannel::accept(
                            stack,
                            &conn,
                            &[H2H_PSM],
                            &l2cap_config,
                        )
                        .await
                        {
                            Ok(mut channel) => {
                                // Protocol: receive initiator's payload first
                                let mut rx_buf = [0u8; 128];
                                match channel.receive(stack, &mut rx_buf).await {
                                    Ok(rx_len) => {
                                        println!("[periph] H2H rx {} bytes", rx_len);
                                        if let Ok(peer_payload) =
                                            H2hPayload::deserialize(&rx_buf[..rx_len])
                                        {
                                            // Resolve partner's short_addr from their pubkey
                                            // (if they included it), or from the routing table.
                                            let partner_short = match peer_payload.full_pubkey {
                                                Some(pk) => short_addr_of(&pk),
                                                None => {
                                                    // Peer didn't send pubkey — look them up by MAC
                                                    let mac = conn.peer_address();
                                                    let mut mac_arr = [0u8; 6];
                                                    mac_arr.copy_from_slice(mac.raw());
                                                    let table = routing_table.lock().await;
                                                    table.peers.iter()
                                                        .find(|p| p.transport_addr.addr == mac_arr)
                                                        .map(|p| p.short_addr)
                                                        .unwrap_or([0u8; 8])
                                                }
                                            };

                                            println!(
                                                "[periph] H2H step=1 partner={:02x?}",
                                                &partner_short[..4]
                                            );

                                            // Send our payload back
                                            let now = Instant::now().as_ticks();
                                            let payload = build_h2h_payload(
                                                identity,
                                                capabilities,
                                                uptime,
                                                routing_table,
                                                &partner_short,
                                                now,
                                            )
                                            .await;
                                            println!("[periph] H2H step=2 built payload, {} peers", payload.peer_count);

                                            // Update routing table BEFORE sending so the
                                            // connection stays alive longer (the conn drops
                                            // when we fall out of this block).
                                            let mac = conn.peer_address();
                                            let mut mac_arr = [0u8; 6];
                                            mac_arr.copy_from_slice(mac.raw());
                                            let transport = TransportAddr {
                                                addr_type: 0,
                                                addr: mac_arr,
                                            };

                                            {
                                                let mut table = routing_table.lock().await;
                                                table.update_peer_from_h2h(
                                                    &peer_payload,
                                                    partner_short,
                                                    transport,
                                                    Instant::now().as_ticks(),
                                                );
                                                println!(
                                                    "[periph] Routing table: {} peers",
                                                    table.peers.len()
                                                );
                                            }

                                            // Now send the response
                                            let mut tx_buf = [0u8; 128];
                                            match payload.serialize(&mut tx_buf) {
                                                Ok(tx_len) => {
                                                    println!("[periph] H2H step=3 serialized {} bytes", tx_len);
                                                    match channel.send(stack, &tx_buf[..tx_len]).await {
                                                        Ok(()) => println!("[periph] H2H step=4 tx ok"),
                                                        Err(e) => println!("[periph] H2H step=4 tx ERR: {:?}", e),
                                                    }
                                                }
                                                Err(e) => {
                                                    println!("[periph] H2H serialize error: {:?}", e);
                                                }
                                            }

                                            // Give the BLE controller time to flush the
                                            // response before `conn` drops and disconnects.
                                            Timer::after(Duration::from_millis(200)).await;
                                        } else {
                                            println!("[periph] H2H deserialize FAILED ({} bytes)", rx_len);
                                        }
                                    }
                                    Err(e) => {
                                        println!("[periph] L2CAP rx error: {:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("[periph] L2CAP accept error: {:?}", e);
                            }
                        }
                        // conn dropped → disconnect
                    }
                    Err(e) => {
                        println!("[periph] Accept error: {:?}", e);
                    }
                }
            }
            Err(e) => {
                println!("[periph] Advertise error: {:?}", e);
                Timer::after(Duration::from_secs(3)).await;
            }
        }
    }
}

// =============================================================================
// Task 3: Central H2H — discovery scan + initiate H2H connections
// =============================================================================

async fn central_h2h_task<'a, C>(
    mut central: Central<'a, C, DefaultPacketPool>,
    stack: &'a Stack<'a, C, DefaultPacketPool>,
    identity: &NodeIdentity,
    capabilities: u16,
    uptime: &'static Mutex<NoopRawMutex, u32>,
    discovery_rx: &'static Channel<NoopRawMutex, (BdAddr, AddrKind, DiscoveryInfo), 4>,
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
) where
    C: Controller
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeSetScanEnable>
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdAsync<LeCreateConn>,
{
    // Startup delay — let peripheral start advertising first
    Timer::after(Duration::from_secs(3)).await;

    loop {
        let cycle_start = Instant::now();

        // ── Phase 1: Discovery scan ──────────────────────────────────────
        // Quick scan to discover new Constellation nodes.
        println!("[central] Discovery scan...");

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
                let deadline = Instant::now() + Duration::from_secs(7);

                while Instant::now() < deadline {
                    let remaining = deadline - Instant::now();
                    match embassy_futures::select::select(
                        discovery_rx.receive(),
                        Timer::after(remaining),
                    )
                    .await
                    {
                        embassy_futures::select::Either::First((bd_addr, _addr_kind, info)) => {
                            let mut mac_arr = [0u8; 6];
                            mac_arr.copy_from_slice(bd_addr.raw());
                            let transport = TransportAddr {
                                addr_type: 0,
                                addr: mac_arr,
                            };

                            let mut table = routing_table.lock().await;
                            let is_new = table.update_peer_compact(
                                info.short_addr,
                                info.capabilities,
                                transport,
                                Instant::now().as_ticks(),
                            );
                            if is_new {
                                println!(
                                    "[central] New peer {:02x?} ({} total)",
                                    info.short_addr,
                                    table.peers.len()
                                );
                            }
                        }
                        embassy_futures::select::Either::Second(_) => break,
                    }
                }
                // Dropping _session stops scanning
            }
            Err(e) => {
                println!("[central] Scan error: {:?}", e);
            }
        }

        central = scanner.into_inner();

        // ── Phase 2: H2H connections ─────────────────────────────────────
        // Connect to each known peer where we are the initiator.

        // Snapshot peer addresses and BLE MACs
        let our_addr = *identity.short_addr();
        let peer_snapshots: heapless::Vec<(ShortAddr, [u8; 6]), 32> = {
            let table = routing_table.lock().await;
            let mut v = heapless::Vec::new();
            for peer in table.peers.iter() {
                // Only initiate if we have a valid transport address
                if peer.transport_addr.addr != [0u8; 6]
                    && h2h::is_initiator(&our_addr, &peer.short_addr)
                {
                    let _ = v.push((peer.short_addr, peer.transport_addr.addr));
                }
            }
            v
        };

        if !peer_snapshots.is_empty() {
            println!(
                "[central] H2H cycle: {} peers to connect",
                peer_snapshots.len()
            );
        }

        for (peer_addr, peer_mac) in peer_snapshots.iter() {
            let offset = h2h::slot_offset(&our_addr, peer_addr);
            let target_time = cycle_start + Duration::from_secs(offset);

            // Wait until our slot
            if Instant::now() < target_time {
                Timer::at(target_time).await;
            }

            println!(
                "[central] H2H → {:02x?} (slot {}s)",
                peer_addr, offset,
            );

            // Connect to the peer
            let bd_addr = BdAddr(*peer_mac);
            let connect_config = ConnectConfig {
                scan_config: ScanConfig {
                    filter_accept_list: &[(AddrKind::RANDOM, &bd_addr)],
                    timeout: Duration::from_secs(H2H_CONNECTION_TIMEOUT_SECS),
                    ..Default::default()
                },
                connect_params: Default::default(),
            };

            match central.connect(&connect_config).await {
                Ok(conn) => {
                    println!("[central] Connected to {:02x?}", peer_addr);

                    let l2cap_config = L2capChannelConfig {
                        mtu: Some(H2H_MTU),
                        ..Default::default()
                    };

                    match L2capChannel::create(stack, &conn, H2H_PSM, &l2cap_config).await {
                        Ok(mut channel) => {
                            // Protocol: initiator sends first
                            let now = Instant::now().as_ticks();
                            let payload =
                                build_h2h_payload(identity, capabilities, uptime, routing_table, peer_addr, now)
                                    .await;
                            let mut tx_buf = [0u8; 128];
                            if let Ok(tx_len) = payload.serialize(&mut tx_buf) {
                                if let Err(e) = channel.send(stack, &tx_buf[..tx_len]).await {
                                    println!("[central] L2CAP send error: {:?}", e);
                                    continue;
                                }
                                println!("[central] H2H tx sent");
                            }

                            // Receive peer's payload
                            let mut rx_buf = [0u8; 128];
                            match channel.receive(stack, &mut rx_buf).await {
                                Ok(rx_len) => {
                                    if let Ok(peer_payload) =
                                        H2hPayload::deserialize(&rx_buf[..rx_len])
                                    {
                                        println!(
                                            "[central] H2H rx from {:02x?}",
                                            peer_addr
                                        );

                                        let transport = TransportAddr {
                                            addr_type: 0,
                                            addr: *peer_mac,
                                        };

                                        let mut table = routing_table.lock().await;
                                        table.update_peer_from_h2h(
                                            &peer_payload,
                                            *peer_addr,
                                            transport,
                                            Instant::now().as_ticks(),
                                        );
                                        println!(
                                            "[central] Routing table: {} peers",
                                            table.peers.len()
                                        );
                                    }
                                }
                                Err(e) => {
                                    println!("[central] L2CAP rx error: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("[central] L2CAP create error: {:?}", e);
                        }
                    }
                    // conn dropped → disconnect
                }
                Err(e) => {
                    println!("[central] Connect to {:02x?} failed: {:?}", peer_addr, e);
                }
            }
        }

        // ── Wait for next cycle ──────────────────────────────────────────
        let elapsed = Instant::now() - cycle_start;
        let cycle = Duration::from_secs(H2H_CYCLE_SECS);
        if elapsed < cycle {
            Timer::after(cycle - elapsed).await;
        }
    }
}

// =============================================================================
// Task 4: Heartbeat update
// =============================================================================

async fn heartbeat_update_task(
    uptime: &'static Mutex<NoopRawMutex, u32>,
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
) {
    loop {
        Timer::after(Duration::from_secs(5)).await;

        {
            let mut u = uptime.lock().await;
            *u = u.saturating_add(5);
        }

        let (up, peers) = {
            let u = uptime.lock().await;
            let table = routing_table.lock().await;
            (*u, table.peers.len())
        };

        println!("[heartbeat] Uptime: {}s, peers: {}", up, peers);
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
