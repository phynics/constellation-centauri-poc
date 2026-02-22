#![no_std]
#![no_main]

// ESP-IDF application descriptor (required for flashing)
esp_bootloader_esp_idf::esp_app_desc!();

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
use transport::ble::PacketBuf;
use transport::gatt::ConstellationServer;

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
static GATT_SERVER: StaticCell<ConstellationServer> = StaticCell::new();

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

    // 3. Initialize esp-rtos scheduler (required for BLE)
    println!("Initializing RTOS scheduler...");
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    #[cfg(target_arch = "riscv32")]
    let software_interrupt = esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);

    esp_rtos::start(
        timg0.timer0,
        #[cfg(target_arch = "riscv32")]
        software_interrupt.software_interrupt0,
    );

    // 4. Initialize RNG and flash storage
    println!("Initializing RNG (non-cryptographic - PoC only)...");
    let mut rng = Rng::new();
    let mut flash = FlashStorage::new(peripherals.FLASH);

    // 5. Identity provisioning
    let identity = load_or_generate_identity(&mut flash, &mut rng);

    println!("Node identity: {:02x?}", identity.short_addr());
    println!("Public key: {:02x?}", identity.pubkey());

    // 6. Initialize BLE controller
    println!("Initializing BLE controller...");
    let bluetooth = peripherals.BT;
    let connector = BleConnector::new(bluetooth, Default::default())
        .expect("Failed to create BLE connector");
    let controller: ExternalController<_, 20> = ExternalController::new(connector);

    // 7. Create BLE host resources
    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();

    // 8. Create BLE stack
    let address = derive_ble_address(&identity);
    println!("BLE address: {:02x?}", address);

    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address);

    let Host {
        mut peripheral,
        runner,
        ..
    } = stack.build();

    // 9. Create shared state
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

    // 10. Create GATT server
    let server = ConstellationServer::new_with_config(GapConfig::default("Cstltn"))
        .expect("Failed to create GATT server");
    let server = GATT_SERVER.init(server);

    println!("GATT server created");
    println!("Ready to advertise and accept connections");

    // 11. Run BLE stack concurrently with application logic
    let _ = join(
        // BLE runner task (must run continuously)
        ble_runner_task(runner),
        // Application task
        app_task(
            &mut peripheral,
            server,
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
async fn ble_runner_task<C: Controller>(mut runner: Runner<'_, C, DefaultPacketPool>) {
    loop {
        if let Err(e) = runner.run().await {
            println!("[ble_runner] error: {:?}", e);
        }
    }
}

/// Main application task
async fn app_task<'a, C: Controller>(
    peripheral: &mut Peripheral<'a, C, DefaultPacketPool>,
    server: &'static ConstellationServer<'static>,
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
    server: &'static ConstellationServer<'static>,
    identity: &NodeIdentity,
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
) -> Result<GattConnection<'a, 'static, DefaultPacketPool>, BleHostError<C::Error>> {
    // Build advertising data with constellation beacon
    let mut adv_data = [0u8; 31];
    let short_addr = identity.short_addr();

    // Keep advertising data minimal to fit in 31 bytes:
    // Flags (3 bytes) + ShortLocalName (8 bytes) + ManufacturerData (12 bytes) = 23 bytes
    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteLocalName(b"Cstltn"), // Shortened to fit
            AdStructure::ManufacturerSpecificData {
                company_identifier: 0x1234,
                payload: short_addr,
            },
        ],
        &mut adv_data[..],
    )?;

    println!("[adv] Starting advertising as 'Cstltn' with beacon for {:02x?}", short_addr);

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
    server: &'static ConstellationServer<'static>,
    _routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
    incoming_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
    _outgoing_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
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
                                // Update the characteristic value before the read response
                                if let Ok(_) = server.mesh_service.heartbeat.set(server, &buf) {
                                    println!("[gatt] Heartbeat data ready");
                                }
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

/// Derive BLE address from node identity
fn derive_ble_address(identity: &NodeIdentity) -> Address {
    let short_addr = identity.short_addr();
    // Use first 6 bytes of ShortAddr for BLE MAC
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&short_addr[0..6]);
    // Set the two most significant bits to 11 for a valid static random address
    mac[5] |= 0xC0; // 0xC0 = 0b11000000
    Address::random(mac)
}
