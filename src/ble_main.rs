/// BLE-integrated main function
/// This will replace the current main.rs once tested

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_println::println;
use esp_radio::ble::controller::BleConnector;
use esp_storage::FlashStorage;
use static_cell::StaticCell;
use trouble_host::prelude::*;

use crate::config::BLOOM_FILTER_BYTES;
use crate::crypto::identity::NodeIdentity;
use crate::node::roles::Capabilities;
use crate::protocol::heartbeat::HeartbeatPayload;
use crate::routing::table::RoutingTable;
use crate::transport::ble::PacketBuf;
use crate::transport::gatt::{ConstellationServer, MeshService};

/// Heap size: 72 KB
const HEAP_SIZE: usize = 72 * 1024;

/// BLE configuration constants
const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2; // Signal + ATT

/// Static cells for shared state
static ROUTING_TABLE: StaticCell<Mutex<NoopRawMutex, RoutingTable>> = StaticCell::new();
static HEARTBEAT: StaticCell<Mutex<NoopRawMutex, HeartbeatPayload>> = StaticCell::new();
static INCOMING_PACKETS: StaticCell<Channel<NoopRawMutex, PacketBuf, 4>> = StaticCell::new();
static OUTGOING_PACKETS: StaticCell<Channel<NoopRawMutex, PacketBuf, 4>> = StaticCell::new();

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    // 1. Initialize heap allocator
    esp_alloc::heap_allocator! {
        size: HEAP_SIZE
    }

    println!("Constellation Mesh Node - BLE PoC");
    println!("==================================");

    // 2. Initialize peripherals
    let peripherals = esp_hal::init(esp_hal::Config::default());

    // 3. Initialize RNG and flash storage
    println!("Initializing RNG (non-cryptographic - PoC only)...");
    let mut rng = Rng::new();
    let mut flash = FlashStorage::new(peripherals.FLASH);

    // 4. Identity provisioning
    let identity = load_or_generate_identity(&mut flash, &mut rng);

    println!("Node identity: {:02x?}", identity.short_addr());
    println!("Public key: {:02x?}", identity.pubkey());

    // 5. Initialize BLE controller
    println!("Initializing BLE controller...");
    let bluetooth = peripherals.BT;
    let connector = BleConnector::new(bluetooth, Default::default())
        .expect("Failed to create BLE connector");
    let controller: ExternalController<_, 20> = ExternalController::new(connector);

    // 6. Create BLE host resources
    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();

    // 7. Create BLE stack
    let address = derive_ble_address(&identity);
    println!("BLE address: {:02x?}", address);

    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address);

    let Host {
        mut peripheral,
        runner,
        ..
    } = stack.build();

    // 8. Create shared state
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

    let incoming_packets = INCOMING_PACKETS.init(Channel::new());
    let outgoing_packets = OUTGOING_PACKETS.init(Channel::new());

    println!("Shared state initialized");

    // 9. Create GATT server
    let server = ConstellationServer::new_with_config(GapConfig::default())
        .expect("Failed to create GATT server");

    println!("GATT server created");
    println!("Ready to advertise and accept connections");

    // 10. Run BLE stack concurrently with application logic
    let _ = join(
        // BLE runner task (must run continuously)
        ble_runner_task(runner),
        // Application task
        app_task(
            &mut peripheral,
            &server,
            identity,
            routing_table,
            heartbeat,
            incoming_packets,
            outgoing_packets,
        ),
    )
    .await;
}

/// Background BLE runner task
async fn ble_runner_task<C: Controller>(mut runner: Runner<'_, C>) {
    loop {
        if let Err(e) = runner.run().await {
            println!("[ble_runner] error: {:?}", e);
        }
    }
}

/// Main application task
async fn app_task<'a, C: Controller>(
    peripheral: &mut Peripheral<'a, C, DefaultPacketPool>,
    server: &'a ConstellationServer<'a>,
    identity: NodeIdentity,
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
    incoming_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
    outgoing_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
) {
    loop {
        // Advertise and wait for connection
        match advertise_and_accept(peripheral, server, &identity, heartbeat).await {
            Ok(conn) => {
                println!("[app] Connection established");

                // Handle the connection
                if let Err(e) = handle_connection(
                    &conn,
                    server,
                    routing_table,
                    heartbeat,
                    incoming_packets,
                    outgoing_packets,
                )
                .await
                {
                    println!("[app] Connection error: {:?}", e);
                }

                println!("[app] Connection closed");
            }
            Err(e) => {
                println!("[app] Advertising error: {:?}", e);
                embassy_futures::yield_now().await;
            }
        }
    }
}

/// Advertise with custom manufacturer data and accept connection
async fn advertise_and_accept<'a, C: Controller>(
    peripheral: &mut Peripheral<'a, C, DefaultPacketPool>,
    server: &'a ConstellationServer<'a>,
    identity: &NodeIdentity,
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
) -> Result<GattConnection<'a, 'a, DefaultPacketPool>, BleHostError<C::Error>> {
    // Build advertising data with constellation beacon
    let mut adv_data = [0u8; 31];
    let short_addr = identity.short_addr();

    // Manufacturer specific data: company ID (0x1234) + ShortAddr (8 bytes)
    let mut manufacturer_data = [0u8; 10];
    manufacturer_data[0..2].copy_from_slice(&0x1234u16.to_le_bytes()); // Company ID
    manufacturer_data[2..10].copy_from_slice(short_addr); // ShortAddr

    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteLocalName(b"Constellation"),
            AdStructure::ServiceUuids16(&[[0x34, 0x12]]), // Service 0x1234
            AdStructure::ManufacturerSpecificData {
                company_identifier: 0x1234,
                payload: short_addr,
            },
        ],
        &mut adv_data[..],
    )?;

    println!("[adv] Starting advertising with beacon for {:02x?}", short_addr);

    // Start advertising
    let advertiser = peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data[..len],
                scan_data: &[],
            },
        )
        .await?;

    println!("[adv] Advertising active, waiting for connection...");

    // Wait for connection and attach GATT server
    let conn = advertiser.accept().await?.with_attribute_server(server)?;

    println!("[adv] Connection accepted");

    Ok(conn)
}

/// Handle GATT connection events
async fn handle_connection<P: PacketPool>(
    conn: &GattConnection<'_, '_, P>,
    server: &ConstellationServer<'_>,
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
    incoming_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
    outgoing_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
) -> Result<(), ()> {
    loop {
        match conn.next().await {
            GattConnectionEvent::Disconnected { reason } => {
                println!("[gatt] Disconnected: {:?}", reason);
                return Ok(());
            }

            GattConnectionEvent::Gatt { event } => {
                match &event {
                    GattEvent::Read(read_event) => {
                        // Handle reads to heartbeat characteristic
                        if read_event.handle() == server.mesh_service.heartbeat.handle {
                            println!("[gatt] Heartbeat read request");

                            let hb = heartbeat.lock().await;
                            let mut buf = [0u8; 71];
                            if let Ok(_) = hb.serialize(&mut buf) {
                                // Read handled automatically by server
                                println!("[gatt] Heartbeat data ready");
                            }
                        }
                    }

                    GattEvent::Write(write_event) => {
                        // Handle writes to packet characteristic
                        if write_event.handle() == server.mesh_service.packets.handle {
                            let data = write_event.data();
                            println!("[gatt] Received packet ({} bytes)", data.len());

                            // Forward to incoming packet channel
                            let mut packet = PacketBuf::new();
                            if packet.extend_from_slice(data).is_ok() {
                                incoming_packets.send(packet).await;
                                println!("[gatt] Packet queued for processing");
                            }
                        }
                    }

                    _ => {}
                }

                // Send response to acknowledge the operation
                match event.accept() {
                    Ok(reply) => {
                        reply.send().await;
                    }
                    Err(e) => {
                        println!("[gatt] Error sending response: {:?}", e);
                    }
                }
            }

            _ => {}
        }
    }
}

/// Load identity from flash or generate new one
fn load_or_generate_identity(flash: &mut FlashStorage, rng: &mut Rng) -> NodeIdentity {
    use crate::node::storage;

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

/// Derive BLE address from node identity
fn derive_ble_address(identity: &NodeIdentity) -> Address {
    let short_addr = identity.short_addr();
    // Use first 6 bytes of ShortAddr for BLE MAC, pad with 0xFF
    let mut mac = [0xFFu8; 6];
    mac[0..6].copy_from_slice(&short_addr[0..6]);
    Address::random(mac)
}
