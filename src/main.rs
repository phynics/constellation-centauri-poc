#![no_std]
#![no_main]

// ESP-IDF application descriptor (required for flashing)
esp_bootloader_esp_idf::esp_app_desc!();

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Timer};
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_println::println;
use esp_storage::FlashStorage;
use static_cell::StaticCell;

pub mod config;
pub mod crypto;
pub mod node;
pub mod protocol;
pub mod routing;
pub mod transport;

use config::BLOOM_FILTER_BYTES;
use crypto::identity::NodeIdentity;
use node::roles::Capabilities;
use protocol::heartbeat::HeartbeatPayload;
use routing::table::RoutingTable;
use transport::ble::{ble_advertise_task, ble_gatt_task, ble_scan_task, PacketBuf};

/// Heap size: 72 KB
const HEAP_SIZE: usize = 72 * 1024;

/// Static cells for shared state.
static ROUTING_TABLE: StaticCell<Mutex<NoopRawMutex, RoutingTable>> = StaticCell::new();
static HEARTBEAT: StaticCell<Mutex<NoopRawMutex, HeartbeatPayload>> = StaticCell::new();
static INCOMING_PACKETS: StaticCell<Channel<NoopRawMutex, PacketBuf, 4>> = StaticCell::new();
static OUTGOING_PACKETS: StaticCell<Channel<NoopRawMutex, PacketBuf, 4>> = StaticCell::new();

/// Main entry point.
///
/// Phase 5 Integration:
/// 1. Initialize heap and peripherals
/// 2. Load or generate node identity from flash
/// 3. Create shared state (routing table, channels)
/// 4. Spawn embassy async tasks for BLE
/// 5. Run main event loop with demo message sending
#[esp_rtos::main]
async fn main(spawner: Spawner) {
    // 1. Initialize heap allocator (72 KB)
    esp_alloc::heap_allocator! {
        size: HEAP_SIZE
    }

    println!("Constellation Mesh Node - Phase 5 PoC");
    println!("======================================");

    // 2. Initialize peripherals
    let peripherals = esp_hal::init(esp_hal::Config::default());

    // Initialize RNG for identity generation
    // ⚠️  WARNING: Using non-cryptographic RNG for PoC/testing only!
    // In production, initialize radio first and use Trng for cryptographic security.
    println!("Initializing RNG (non-cryptographic - PoC only)...");
    let mut rng = Rng::new();

    // Initialize flash storage for identity persistence
    let mut flash = FlashStorage::new(peripherals.FLASH);

    // 3. Identity provisioning
    // Load from flash if provisioned, otherwise generate new identity
    let identity = match node::storage::is_provisioned(&mut flash) {
        Ok(true) => {
            println!("Loading identity from flash...");
            match node::storage::load_identity(&mut flash) {
                Ok(id) => {
                    println!("Identity loaded successfully");
                    id
                }
                Err(e) => {
                    println!("Failed to load identity: {:?}", e);
                    println!("Generating new identity...");
                    let id = NodeIdentity::generate_insecure(&mut rng);
                    if let Err(e) = node::storage::save_identity(&mut flash, &id) {
                        println!("Warning: Failed to save identity: {:?}", e);
                    }
                    id
                }
            }
        }
        Ok(false) | Err(_) => {
            println!("No identity found. Generating new identity...");
            let id = NodeIdentity::generate_insecure(&mut rng);
            match node::storage::save_identity(&mut flash, &id) {
                Ok(_) => println!("Identity saved to flash"),
                Err(e) => println!("Warning: Failed to save identity: {:?}", e),
            }
            id
        }
    };

    println!(
        "Node identity: {:02x?}",
        identity.short_addr()
    );
    println!("Public key: {:02x?}", identity.pubkey());

    // 4. Create routing table
    let routing_table = RoutingTable::new(*identity.short_addr());
    let routing_table = ROUTING_TABLE.init(Mutex::new(routing_table));

    // 5. Create initial heartbeat payload
    let capabilities = Capabilities(Capabilities::ROUTE | Capabilities::APPLICATION);
    let heartbeat_payload = HeartbeatPayload {
        full_pubkey: identity.pubkey(),
        capabilities: capabilities.0,
        uptime_secs: 0,
        bloom_filter: [0u8; BLOOM_FILTER_BYTES],
        bloom_generation: 0,
    };
    let heartbeat = HEARTBEAT.init(Mutex::new(heartbeat_payload));

    // 6. Create packet channels
    let incoming_packets = INCOMING_PACKETS.init(Channel::new());
    let outgoing_packets = OUTGOING_PACKETS.init(Channel::new());

    println!("Shared state initialized");

    // 7. Spawn BLE tasks
    // Note: These tasks are currently skeletons. Full BLE integration
    // with trouble-host will be completed when the BLE API is stabilized.
    spawner
        .spawn(advertise_task(*identity.short_addr()))
        .ok();
    spawner.spawn(scan_task(routing_table)).ok();
    spawner
        .spawn(gatt_task(heartbeat, incoming_packets, outgoing_packets))
        .ok();

    println!("BLE tasks spawned");

    // 8. Spawn main logic task
    spawner.spawn(main_logic_task(routing_table)).ok();

    println!("Main logic task spawned");
    println!("Node is running. Waiting for peer discovery...");

    // Main executor loop - keep the executor alive
    // The spawned tasks will run concurrently
    loop {
        Timer::after(Duration::from_secs(10)).await;

        // Periodic status log
        let table = routing_table.lock().await;
        println!("Status: {} peers in routing table", table.peers.len());
    }
}

/// BLE advertising task wrapper.
#[embassy_executor::task]
async fn advertise_task(short_addr: [u8; 8]) {
    ble_advertise_task(short_addr).await;
}

/// BLE scanning task wrapper.
#[embassy_executor::task]
async fn scan_task(routing_table: &'static Mutex<NoopRawMutex, RoutingTable>) {
    ble_scan_task(routing_table).await;
}

/// BLE GATT task wrapper.
#[embassy_executor::task]
async fn gatt_task(
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
    incoming: &'static Channel<NoopRawMutex, PacketBuf, 4>,
    outgoing: &'static Channel<NoopRawMutex, PacketBuf, 4>,
) {
    ble_gatt_task(heartbeat, incoming, outgoing).await;
}

/// Main logic task.
///
/// Handles:
/// - Periodic heartbeat generation
/// - Demo message sending when peers are discovered
/// - Routing table maintenance
#[embassy_executor::task]
async fn main_logic_task(routing_table: &'static Mutex<NoopRawMutex, RoutingTable>) {
    let mut uptime_secs: u32 = 0;
    let mut message_sent = false;

    loop {
        Timer::after(Duration::from_secs(1)).await;
        uptime_secs = uptime_secs.wrapping_add(1);

        // Every 60 seconds, log routing table and attempt demo message
        if uptime_secs % 60 == 0 {
            let table = routing_table.lock().await;

            println!("Uptime: {} seconds", uptime_secs);
            println!("Routing table: {} peers", table.peers.len());

            if !table.peers.is_empty() {
                println!("Peers:");
                for (i, peer) in table.peers.iter().enumerate() {
                    println!(
                        "  [{}] {:02x?} (caps: 0x{:04x}, hops: {})",
                        i,
                        peer.short_addr,
                        peer.capabilities,
                        peer.hop_count
                    );
                }

                // Demo: Send encrypted message to first peer (once)
                if !message_sent {
                    let peer = &table.peers[0];
                    println!(
                        "Demo: Would send encrypted message to {:02x?}",
                        peer.short_addr
                    );
                    // TODO: Implement actual encrypted message sending
                    // let plaintext = b"hello from constellation";
                    // let nonce = [0u8; 12]; // TODO: Generate random nonce
                    // let mut encrypted = [0u8; 128];
                    // let len = encrypt(identity, &peer.pubkey, plaintext, &nonce, &mut encrypted)?;
                    // send_packet_via_ble(&peer.transport_addr, &encrypted[..len]).await;

                    message_sent = true;
                }
            }
        }
    }
}
