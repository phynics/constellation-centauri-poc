// =============================================================================
// Constellation Mesh Node — BLE Firmware for ESP32
// =============================================================================
//
// ARCHITECTURE OVERVIEW
// ---------------------
// Each node broadcasts heartbeats via BLE advertising and receives heartbeats
// from peers via scanning. No BLE connections are needed.
//
//   advertise_task:  Periodically broadcasts a compact heartbeat payload
//                    as ManufacturerSpecificData in legacy BLE advertising.
//
//   scan_task:       Runs passive scans; the scan event handler parses
//                    incoming heartbeats and pushes them into a channel.
//                    The scan_task drains the channel and updates the
//                    routing table.
//
// Legacy advertising (31-byte limit) carries a 15-byte compact heartbeat:
//   short_addr(8) + capabilities(2) + uptime(4) + bloom_gen(1)
// The full pubkey and bloom filter are exchanged later via connections.
//
// CONCURRENCY MODEL
// -----------------
// Four tasks run concurrently via `join4`:
//
//   1. ble_runner_task      — Pumps the HCI event loop
//   2. advertise_task       — Broadcast compact heartbeat
//   3. scan_task            — Passive scan, drain heartbeat channel
//   4. heartbeat_update_task — Tick uptime counter every 5 seconds
//
// Legacy advertising and scanning coexist on ESP32-C6 — the controller
// interleaves them at the link layer. No time-division multiplexing needed.
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
    LeSetScanEnable,
    LeSetScanParams,
};
use bt_hci::controller::ControllerCmdSync;

pub mod config;
pub mod crypto;
pub mod node;
pub mod protocol;
pub mod routing;
pub mod transport;

use config::BLOOM_FILTER_BYTES;
use crypto::identity::{ShortAddr, NodeIdentity};
use node::roles::Capabilities;
use protocol::heartbeat::HeartbeatPayload;
use routing::table::{RoutingTable, TransportAddr};

// =============================================================================
// Constants
// =============================================================================

const HEAP_SIZE: usize = 72 * 1024;
const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 3;
const CONSTELLATION_COMPANY_ID: u16 = 0x1234;

/// Compact heartbeat payload for legacy BLE advertising.
/// Layout: [short_addr: 8][capabilities: 2][uptime: 4][bloom_gen: 1] = 15 bytes
const COMPACT_HEARTBEAT_SIZE: usize = 8 + 2 + 4 + 1;

// =============================================================================
// Compact heartbeat (over-the-air format for legacy advertising)
// =============================================================================

/// Parsed compact heartbeat from a BLE advertisement.
struct CompactHeartbeat {
    short_addr: ShortAddr,
    capabilities: u16,
    uptime_secs: u32,
    bloom_generation: u8,
}

fn serialize_compact_heartbeat(
    identity: &NodeIdentity,
    hb: &HeartbeatPayload,
    buf: &mut [u8],
) -> Option<usize> {
    if buf.len() < COMPACT_HEARTBEAT_SIZE {
        return None;
    }
    let sa = identity.short_addr();
    buf[0..8].copy_from_slice(sa);
    buf[8..10].copy_from_slice(&hb.capabilities.to_le_bytes());
    buf[10..14].copy_from_slice(&hb.uptime_secs.to_le_bytes());
    buf[14] = hb.bloom_generation;
    Some(COMPACT_HEARTBEAT_SIZE)
}

fn deserialize_compact_heartbeat(data: &[u8]) -> Option<CompactHeartbeat> {
    if data.len() < COMPACT_HEARTBEAT_SIZE {
        return None;
    }
    let mut short_addr = [0u8; 8];
    short_addr.copy_from_slice(&data[0..8]);
    let capabilities = u16::from_le_bytes([data[8], data[9]]);
    let uptime_secs = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
    let bloom_generation = data[14];
    Some(CompactHeartbeat {
        short_addr,
        capabilities,
        uptime_secs,
        bloom_generation,
    })
}

// =============================================================================
// Shared static state
// =============================================================================

static ROUTING_TABLE: StaticCell<Mutex<NoopRawMutex, RoutingTable>> = StaticCell::new();
static HEARTBEAT: StaticCell<Mutex<NoopRawMutex, HeartbeatPayload>> = StaticCell::new();

/// Channel for the scan handler (synchronous callback) to pass received
/// compact heartbeats to the scan_task (async).
static HEARTBEAT_RX: StaticCell<Channel<NoopRawMutex, (BdAddr, AddrKind, CompactHeartbeat), 4>> =
    StaticCell::new();

// =============================================================================
// Entry point
// =============================================================================

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    esp_alloc::heap_allocator! {
        size: HEAP_SIZE
    }

    println!("Constellation Mesh Node - BLE Advertising Broadcast");
    println!("====================================================");

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
    println!("Public key: {:02x?}", identity.pubkey());

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

    let capabilities = Capabilities(Capabilities::ROUTE | Capabilities::APPLICATION);
    let heartbeat_payload = HeartbeatPayload {
        full_pubkey: identity.pubkey(),
        capabilities: capabilities.0,
        uptime_secs: 0,
        bloom_filter: [0u8; BLOOM_FILTER_BYTES],
        bloom_generation: 0,
    };
    let heartbeat = HEARTBEAT.init(Mutex::new(heartbeat_payload));

    let heartbeat_rx = HEARTBEAT_RX.init(Channel::new());

    let scan_handler = ConstellationScanHandler {
        our_addr: address,
        heartbeat_rx,
    };

    println!("Ready to advertise and scan (legacy, connectionless)");

    let _ = join4(
        ble_runner_task(runner, &scan_handler),
        advertise_task(&mut peripheral, &identity, heartbeat),
        scan_task(central, heartbeat_rx, routing_table),
        heartbeat_update_task(heartbeat, routing_table),
    )
    .await;
}

// =============================================================================
// Heartbeat logging helpers
// =============================================================================

fn format_capabilities(caps: u16) -> &'static str {
    match caps {
        c if c == Capabilities::ROUTE | Capabilities::APPLICATION => "ROUTE | APPLICATION",
        c if c == Capabilities::ROUTE => "ROUTE",
        c if c == Capabilities::APPLICATION => "APPLICATION",
        c if c == Capabilities::ROUTE | Capabilities::STORE => "ROUTE | STORE",
        c if c == Capabilities::ROUTE | Capabilities::APPLICATION | Capabilities::STORE => {
            "ROUTE | APPLICATION | STORE"
        }
        _ => "OTHER",
    }
}

fn log_heartbeat_tx(hb: &HeartbeatPayload, short_addr: &ShortAddr) {
    println!("[heartbeat:tx] Broadcasting heartbeat:");
    println!("  Node ID:      {:02x?}", short_addr);
    println!("  Capabilities: {}", format_capabilities(hb.capabilities));
    println!("  Uptime:       {}s", hb.uptime_secs);
    println!("  Bloom gen:    {}", hb.bloom_generation);
}

fn log_heartbeat_rx(chb: &CompactHeartbeat) {
    println!("[heartbeat:rx] Received from peer:");
    println!("  Node ID:      {:02x?}", chb.short_addr);
    println!("  Capabilities: {}", format_capabilities(chb.capabilities));
    println!("  Uptime:       {}s", chb.uptime_secs);
    println!("  Bloom gen:    {}", chb.bloom_generation);
}

// =============================================================================
// BLE advertising data parser
// =============================================================================

/// Parse AD structures from raw advertising data, looking for
/// ManufacturerSpecificData with our company ID (0x1234). If found,
/// deserialize the payload as a CompactHeartbeat.
fn parse_heartbeat_from_adv(data: &[u8]) -> Option<CompactHeartbeat> {
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
                    return deserialize_compact_heartbeat(&data[payload_start..payload_end]);
                }
            }
        }
        i += 1 + len;
    }
    None
}

// =============================================================================
// Scan event handler
// =============================================================================

struct ConstellationScanHandler {
    our_addr: Address,
    heartbeat_rx: &'static Channel<NoopRawMutex, (BdAddr, AddrKind, CompactHeartbeat), 4>,
}

impl EventHandler for ConstellationScanHandler {
    fn on_adv_reports(&self, mut it: LeAdvReportsIter<'_>) {
        while let Some(Ok(report)) = it.next() {
            if report.addr.raw() == self.our_addr.addr.raw() {
                continue;
            }

            if let Some(chb) = parse_heartbeat_from_adv(report.data) {
                println!(
                    "[scan] Received heartbeat from {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} (RSSI: {})",
                    report.addr.raw()[5], report.addr.raw()[4], report.addr.raw()[3],
                    report.addr.raw()[2], report.addr.raw()[1], report.addr.raw()[0],
                    report.rssi,
                );
                let _ = self.heartbeat_rx.try_send((report.addr, report.addr_kind, chb));
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
// Task 2: Advertise compact heartbeat (legacy BLE advertising)
// =============================================================================

/// Broadcasts a compact heartbeat via legacy NonconnectableNonscannableUndirected
/// advertising. Restarts every cycle with fresh data.
///
/// Advertise duration uses a prime (3s) so that two nodes' cycles naturally
/// drift and overlap — one node advertises while the other scans.
async fn advertise_task<'a, C: Controller>(
    peripheral: &mut Peripheral<'a, C, DefaultPacketPool>,
    identity: &NodeIdentity,
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
) {
    // Per-node startup jitter to break synchronization between nodes.
    let jitter_ms = u16::from_le_bytes([identity.short_addr()[0], identity.short_addr()[1]]) % 2048;
    println!("[adv] Startup jitter: {}ms", jitter_ms);
    Timer::after(Duration::from_millis(jitter_ms as u64)).await;

    loop {
        // Serialize compact heartbeat into MfgSpecificData
        let mut compact_buf = [0u8; COMPACT_HEARTBEAT_SIZE];
        {
            let hb = heartbeat.lock().await;
            if serialize_compact_heartbeat(identity, &hb, &mut compact_buf).is_none() {
                println!("[adv] Failed to serialize heartbeat");
                Timer::after(Duration::from_secs(3)).await;
                continue;
            }
            log_heartbeat_tx(&hb, identity.short_addr());
        }

        let mut adv_data = [0u8; 31];
        let len = match AdStructure::encode_slice(
            &[
                AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                AdStructure::ManufacturerSpecificData {
                    company_identifier: CONSTELLATION_COMPANY_ID,
                    payload: &compact_buf,
                },
            ],
            &mut adv_data[..],
        ) {
            Ok(len) => len,
            Err(e) => {
                println!("[adv] Failed to encode AD structures: {:?}", e);
                Timer::after(Duration::from_secs(3)).await;
                continue;
            }
        };

        println!("[adv] Broadcasting heartbeat ({} bytes)...", len);

        match peripheral
            .advertise(
                &Default::default(),
                Advertisement::NonconnectableNonscannableUndirected {
                    adv_data: &adv_data[..len],
                },
            )
            .await
        {
            Ok(_advertiser) => {
                // Advertising runs in the controller. Sleep for one cycle.
                // 3 seconds (prime) — coprime with scan duration (7s) to
                // ensure phase rotation between nodes.
                Timer::after(Duration::from_secs(3)).await;
                // Dropping _advertiser stops advertising
            }
            Err(e) => {
                println!("[adv] Advertising error: {:?}", e);
                Timer::after(Duration::from_secs(3)).await;
            }
        }
    }
}

// =============================================================================
// Task 3: Scan for peer heartbeats
// =============================================================================

/// Runs passive scans and drains the heartbeat channel into the routing table.
///
/// Scan duration uses a prime (7s) — coprime with the advertise duration (3s)
/// so that two nodes' windows naturally rotate and overlap.
async fn scan_task<'a, C>(
    central: Central<'a, C, DefaultPacketPool>,
    heartbeat_rx: &'static Channel<NoopRawMutex, (BdAddr, AddrKind, CompactHeartbeat), 4>,
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
) where
    C: Controller
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeSetScanEnable>
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
{
    let mut scanner = Scanner::new(central);

    loop {
        println!("[scan] Scanning for peers...");

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
                        heartbeat_rx.receive(),
                        Timer::after(remaining),
                    )
                    .await
                    {
                        embassy_futures::select::Either::First((bd_addr, _addr_kind, chb)) => {
                            let mac = bd_addr.raw();
                            let mut mac_arr = [0u8; 6];
                            mac_arr.copy_from_slice(mac);
                            let transport = TransportAddr {
                                addr_type: 0,
                                addr: mac_arr,
                            };

                            let mut table = routing_table.lock().await;
                            table.update_peer_compact(
                                chb.short_addr,
                                chb.capabilities,
                                transport,
                                Instant::now().as_ticks(),
                            );
                            println!(
                                "  -> Routing table updated ({} peers)",
                                table.peers.len()
                            );

                            log_heartbeat_rx(&chb);
                        }
                        embassy_futures::select::Either::Second(_) => {
                            break;
                        }
                    }
                }
                // Dropping _session stops scanning
            }
            Err(e) => {
                println!("[scan] Scan error: {:?}", e);
                Timer::after(Duration::from_secs(7)).await;
            }
        }
    }
}

// =============================================================================
// Task 4: Heartbeat update
// =============================================================================

async fn heartbeat_update_task(
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
) {
    let mut uptime_secs: u32 = 0;

    loop {
        Timer::after(Duration::from_secs(5)).await;

        uptime_secs = uptime_secs.saturating_add(5);
        {
            let mut hb = heartbeat.lock().await;
            hb.uptime_secs = uptime_secs;

            let table = routing_table.lock().await;
            hb.bloom_filter = table.local_bloom.bits;
            hb.bloom_generation = table.bloom_generation;
        }

        println!("[heartbeat] Uptime: {}s, peers: {}", uptime_secs, {
            let table = routing_table.lock().await;
            table.peers.len()
        });
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
