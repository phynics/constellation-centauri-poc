#![no_std]
#![no_main]

// ESP-IDF application descriptor (required for flashing)
esp_bootloader_esp_idf::esp_app_desc!();

use embassy_executor::Spawner;
use embassy_futures::join::join4;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
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
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeCreateConn, LeSetScanEnable,
    LeSetScanParams,
};
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};

pub mod config;
pub mod crypto;
pub mod node;
pub mod protocol;
pub mod routing;
pub mod transport;

use config::BLOOM_FILTER_BYTES;
use crypto::identity::{short_addr_of, NodeIdentity};
use node::roles::Capabilities;
use protocol::heartbeat::HeartbeatPayload;
use routing::table::RoutingTable;
use transport::ble::PacketBuf;
use transport::gatt::ConstellationServer;
use routing::table::TransportAddr;

/// Heap size: 72 KB
const HEAP_SIZE: usize = 72 * 1024;

/// BLE configuration constants
const CONNECTIONS_MAX: usize = 2; // 1 peripheral + 1 central
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + ATT per connection

/// Constellation manufacturer ID used in advertising
const CONSTELLATION_COMPANY_ID: u16 = 0x1234;

/// Static cells for shared state
static ROUTING_TABLE: StaticCell<Mutex<NoopRawMutex, RoutingTable>> = StaticCell::new();
static HEARTBEAT: StaticCell<Mutex<NoopRawMutex, HeartbeatPayload>> = StaticCell::new();
static INCOMING_PACKETS: StaticCell<Channel<NoopRawMutex, PacketBuf, 4>> = StaticCell::new();
static OUTGOING_PACKETS: StaticCell<Channel<NoopRawMutex, PacketBuf, 4>> = StaticCell::new();
static GATT_SERVER: StaticCell<ConstellationServer> = StaticCell::new();
static DISCOVERED_PEER: StaticCell<Signal<NoopRawMutex, Address>> = StaticCell::new();

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
        central,
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
    let discovered_peer = DISCOVERED_PEER.init(Signal::new());

    println!("Shared state initialized");

    // 10. Create GATT server
    let server = ConstellationServer::new_with_config(GapConfig::default("Cstltn"))
        .expect("Failed to create GATT server");
    let server = GATT_SERVER.init(server);

    // 11. Create scan handler for discovering Constellation peers
    let scan_handler = ConstellationScanHandler {
        our_addr: address,
        discovered: discovered_peer,
    };

    println!("GATT server created");
    println!("Ready to advertise, scan, and connect");

    // 12. Run BLE stack concurrently with application logic
    let _ = join4(
        // BLE runner task with scan event handler
        ble_runner_task(runner, &scan_handler),
        // Peripheral role: advertise + accept connections + serve GATT
        peripheral_task(
            &mut peripheral,
            server,
            &identity,
            routing_table,
            heartbeat,
            incoming_packets,
            outgoing_packets,
        ),
        // Central role: scan + connect + subscribe to peer heartbeats
        central_task(
            central,
            &stack,
            discovered_peer,
            routing_table,
            heartbeat,
        ),
        // Heartbeat update task (periodic uptime + bloom updates)
        heartbeat_update_task(server, heartbeat, routing_table),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Heartbeat logging helpers
// ---------------------------------------------------------------------------

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

fn log_heartbeat_tx(hb: &HeartbeatPayload) {
    let node_id = short_addr_of(&hb.full_pubkey);
    println!("[heartbeat:tx] Sending heartbeat:");
    println!("  Node ID:      {:02x?}", node_id);
    println!("  Pubkey:       {:02x?}...", &hb.full_pubkey[..8]);
    println!("  Capabilities: {}", format_capabilities(hb.capabilities));
    println!("  Uptime:       {}s", hb.uptime_secs);
    println!("  Bloom gen:    {}", hb.bloom_generation);
}

fn log_heartbeat_rx(hb: &HeartbeatPayload) {
    let node_id = short_addr_of(&hb.full_pubkey);
    println!("[heartbeat:rx] Received from peer:");
    println!("  Node ID:      {:02x?}", node_id);
    println!("  Pubkey:       {:02x?}...", &hb.full_pubkey[..8]);
    println!("  Capabilities: {}", format_capabilities(hb.capabilities));
    println!("  Uptime:       {}s", hb.uptime_secs);
    println!("  Bloom gen:    {}", hb.bloom_generation);
}

// ---------------------------------------------------------------------------
// BLE advertising data parsing
// ---------------------------------------------------------------------------

/// Parse BLE advertising data (AD structures) looking for Constellation manufacturer data.
/// AD structure format: [length, type, data...]
/// Type 0xFF = Manufacturer Specific Data, first 2 bytes = company ID (LE).
fn is_constellation_adv(data: &[u8]) -> bool {
    let mut i = 0;
    while i + 1 < data.len() {
        let len = data[i] as usize;
        if len == 0 || i + 1 + len > data.len() {
            break;
        }
        let ad_type = data[i + 1];
        // Manufacturer Specific Data type = 0xFF, needs at least 2 bytes for company ID
        if ad_type == 0xFF && len >= 3 {
            let company_id = u16::from_le_bytes([data[i + 2], data[i + 3]]);
            if company_id == CONSTELLATION_COMPANY_ID {
                return true;
            }
        }
        i += 1 + len;
    }
    false
}

// ---------------------------------------------------------------------------
// Scan event handler
// ---------------------------------------------------------------------------

/// EventHandler that filters BLE scan reports for Constellation nodes.
/// When a peer is discovered, signals the central task via a Signal.
struct ConstellationScanHandler {
    our_addr: Address,
    discovered: &'static Signal<NoopRawMutex, Address>,
}

impl EventHandler for ConstellationScanHandler {
    fn on_adv_reports(&self, mut it: LeAdvReportsIter<'_>) {
        while let Some(Ok(report)) = it.next() {
            // Skip our own advertisements
            if report.addr.raw() == self.our_addr.addr.raw() {
                continue;
            }

            // Check if this is a Constellation node
            if is_constellation_adv(report.data) {
                let peer_addr = Address {
                    kind: report.addr_kind,
                    addr: report.addr,
                };
                println!(
                    "[scan] Discovered Constellation peer: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} (RSSI: {})",
                    report.addr.raw()[5], report.addr.raw()[4], report.addr.raw()[3],
                    report.addr.raw()[2], report.addr.raw()[1], report.addr.raw()[0],
                    report.rssi,
                );
                self.discovered.signal(peer_addr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BLE runner task
// ---------------------------------------------------------------------------

/// Background BLE runner task with scan event handler
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

// ---------------------------------------------------------------------------
// Heartbeat update task
// ---------------------------------------------------------------------------

/// Periodic heartbeat update task
/// Updates uptime counter and bloom filter every 5 seconds
async fn heartbeat_update_task(
    _server: &'static ConstellationServer<'static>,
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

            // Sync bloom filter from routing table
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

// ---------------------------------------------------------------------------
// Peripheral task (existing, refactored)
// ---------------------------------------------------------------------------

/// Peripheral role: advertise, accept connections, serve GATT
async fn peripheral_task<'a, C: Controller>(
    peripheral: &mut Peripheral<'a, C, DefaultPacketPool>,
    server: &'static ConstellationServer<'static>,
    identity: &NodeIdentity,
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
    incoming_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
    outgoing_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
) {
    loop {
        match advertise_and_accept(peripheral, server, identity, heartbeat).await {
            Ok(conn) => {
                println!("[peripheral] Connection established");

                if let Err(e) = handle_peripheral_connection(
                    &conn,
                    server,
                    routing_table,
                    heartbeat,
                    incoming_packets,
                    outgoing_packets,
                )
                .await
                {
                    println!("[peripheral] Connection error: {:?}", e);
                }

                println!("[peripheral] Connection closed");
            }
            Err(e) => {
                println!("[peripheral] Advertising error: {:?}", e);
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
    _heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
) -> Result<GattConnection<'a, 'static, DefaultPacketPool>, BleHostError<C::Error>> {
    let mut adv_data = [0u8; 31];
    let short_addr = identity.short_addr();

    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteLocalName(b"Cstltn"),
            AdStructure::ManufacturerSpecificData {
                company_identifier: CONSTELLATION_COMPANY_ID,
                payload: short_addr,
            },
        ],
        &mut adv_data[..],
    )?;

    println!("[adv] Advertising as 'Cstltn' beacon={:02x?}", short_addr);

    let advertiser = peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data[..len],
                scan_data: &[],
            },
        )
        .await?;

    println!("[adv] Waiting for connection...");

    let conn = advertiser.accept().await?.with_attribute_server(server)?;

    println!("[adv] Connection accepted");

    Ok(conn)
}

/// Handle GATT connection events (peripheral/server side)
async fn handle_peripheral_connection<P: PacketPool>(
    conn: &GattConnection<'_, '_, P>,
    server: &'static ConstellationServer<'static>,
    _routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
    heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
    incoming_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
    _outgoing_packets: &'static Channel<NoopRawMutex, PacketBuf, 4>,
) -> Result<(), ()> {
    use embassy_futures::select::{select, Either};

    loop {
        match select(conn.next(), Timer::after(Duration::from_secs(10))).await {
            Either::First(event) => match event {
                GattConnectionEvent::Disconnected { reason } => {
                    println!("[gatt] Disconnected: {:?}", reason);
                    return Ok(());
                }

                GattConnectionEvent::Gatt { event } => {
                    match &event {
                        GattEvent::Read(read_event) => {
                            if read_event.handle() == server.mesh_service.heartbeat.handle {
                                let hb = heartbeat.lock().await;
                                let mut buf = [0u8; 71];
                                if let Ok(_) = hb.serialize(&mut buf) {
                                    log_heartbeat_tx(&hb);
                                    let _ = server.mesh_service.heartbeat.set(server, &buf);
                                }
                            }
                        }

                        GattEvent::Write(write_event) => {
                            if write_event.handle() == server.mesh_service.packets.handle {
                                let data = write_event.data();
                                println!("[gatt] Received packet ({} bytes)", data.len());
                                let mut packet = PacketBuf::new();
                                if packet.extend_from_slice(data).is_ok() {
                                    incoming_packets.send(packet).await;
                                }
                            }
                        }

                        _ => {}
                    }

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
            },
            Either::Second(_) => {
                // Send periodic heartbeat notification
                let hb = heartbeat.lock().await;
                let mut buf = [0u8; 71];
                if let Ok(_) = hb.serialize(&mut buf) {
                    log_heartbeat_tx(&hb);

                    if let Ok(_) = server.mesh_service.heartbeat.set(server, &buf) {
                        if let Ok(_) = server.mesh_service.heartbeat.notify(conn, &buf).await {
                            println!("  -> Notification sent ({} bytes)", buf.len());
                        } else {
                            println!("  -> Notification failed (not subscribed?)");
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Central task (new): scan, connect, subscribe to peer heartbeats
// ---------------------------------------------------------------------------

/// Central role: scan for Constellation peers, connect, discover GATT services,
/// subscribe to heartbeat notifications, and update routing table.
async fn central_task<'a, C>(
    central: Central<'a, C, DefaultPacketPool>,
    stack: &'a Stack<'a, C, DefaultPacketPool>,
    discovered_peer: &'static Signal<NoopRawMutex, Address>,
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
    _heartbeat: &'static Mutex<NoopRawMutex, HeartbeatPayload>,
) where
    C: Controller
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeSetScanEnable>
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdAsync<LeCreateConn>,
{
    let mut scanner = Scanner::new(central);

    loop {
        // Phase 1: Scan for Constellation peers
        println!("[central] Scanning for Constellation peers...");
        discovered_peer.reset();

        let scan_config = ScanConfig {
            active: false,
            phys: PhySet::M1,
            interval: Duration::from_millis(100),
            window: Duration::from_millis(100),
            ..Default::default()
        };

        let peer_addr = match scanner.scan(&scan_config).await {
            Ok(session) => {
                // Wait for a peer to be discovered via the EventHandler (with timeout)
                let result = embassy_futures::select::select(
                    discovered_peer.wait(),
                    Timer::after(Duration::from_secs(30)),
                )
                .await;

                drop(session); // Stop scanning

                match result {
                    embassy_futures::select::Either::First(addr) => {
                        discovered_peer.reset();
                        addr
                    }
                    embassy_futures::select::Either::Second(_) => {
                        println!("[central] No peers found, retrying...");
                        continue;
                    }
                }
            }
            Err(e) => {
                println!("[central] Scan error: {:?}", e);
                Timer::after(Duration::from_secs(5)).await;
                continue;
            }
        };

        // Phase 2: Connect to the discovered peer
        // Get Central back from Scanner (connect() requires Central, not Scanner)
        let mut central = scanner.into_inner();

        println!("[central] Connecting to peer...");

        let connect_config = ConnectConfig {
            connect_params: Default::default(),
            scan_config: ScanConfig {
                filter_accept_list: &[(peer_addr.kind, &peer_addr.addr)],
                ..Default::default()
            },
        };

        match central.connect(&connect_config).await {
            Ok(conn) => {
                println!("[central] Connected to peer!");

                // Phase 3: GATT client operations
                if let Err(e) =
                    handle_central_connection(&conn, stack, routing_table).await
                {
                    println!("[central] Connection handling error: {:?}", e);
                }

                println!("[central] Peer connection closed, will re-scan");
            }
            Err(e) => {
                println!("[central] Connect failed: {:?}", e);
            }
        }

        // Wrap central back into Scanner for next iteration
        scanner = Scanner::new(central);

        // Brief delay before re-scanning
        Timer::after(Duration::from_secs(2)).await;
    }
}

/// Handle a central-role connection: discover services, subscribe to heartbeat,
/// receive notifications and update routing table.
async fn handle_central_connection<'a, C: Controller, P: PacketPool>(
    conn: &Connection<'a, P>,
    stack: &'a Stack<'a, C, P>,
    routing_table: &'static Mutex<NoopRawMutex, RoutingTable>,
) -> Result<(), &'static str> {
    // Create GATT client (performs MTU exchange)
    let client = GattClient::<C, P, 10>::new(stack, conn)
        .await
        .map_err(|_| "Failed to create GATT client")?;

    println!("[central] GATT client created, discovering services...");

    // The client.task() must run concurrently with our GATT operations
    let _ = embassy_futures::join::join(
        client.task(),
        async {
            // Discover Constellation mesh service by UUID
            // UUID "12345678-9abc-def0-1234-56789abcdef1" in BLE little-endian byte order
            let service_uuid = Uuid::new_long([
                0xf1, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a, 0x78,
                0x56, 0x34, 0x12,
            ]);

            let services = match client.services_by_uuid(&service_uuid).await {
                Ok(s) => s,
                Err(e) => {
                    println!("[central] Service discovery failed: {:?}", e);
                    return;
                }
            };

            let service = match services.first() {
                Some(s) => s,
                None => {
                    println!("[central] Constellation service not found");
                    return;
                }
            };

            println!("[central] Found Constellation mesh service");

            // Discover heartbeat characteristic by UUID
            // UUID "12345678-9abc-def0-1234-56789abcdef2" in BLE little-endian byte order
            let heartbeat_uuid = Uuid::new_long([
                0xf2, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a, 0x78,
                0x56, 0x34, 0x12,
            ]);

            let hb_char: Characteristic<[u8; 71]> = match client
                .characteristic_by_uuid(service, &heartbeat_uuid)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    println!("[central] Heartbeat characteristic not found: {:?}", e);
                    return;
                }
            };

            println!("[central] Found heartbeat characteristic");

            // Read the current heartbeat value
            let mut hb_buf = [0u8; 71];
            match client.read_characteristic(&hb_char, &mut hb_buf).await {
                Ok(len) => {
                    println!("[central] Initial heartbeat read ({} bytes)", len);
                    if let Ok(hb) = HeartbeatPayload::deserialize(&hb_buf[..len]) {
                        log_heartbeat_rx(&hb);
                        update_routing_table_from_conn(conn, &hb, routing_table).await;
                    }
                }
                Err(e) => {
                    println!("[central] Read failed: {:?}", e);
                }
            }

            // Subscribe to heartbeat notifications
            println!("[central] Subscribing to heartbeat notifications...");
            let mut listener = match client.subscribe(&hb_char, false).await {
                Ok(l) => l,
                Err(e) => {
                    println!("[central] Failed to subscribe: {:?}", e);
                    return;
                }
            };

            println!("[central] Subscribed! Listening for heartbeat notifications...");

            // Receive heartbeat notifications until disconnection
            loop {
                let notification = listener.next().await;
                let data = notification.as_ref();

                if let Ok(hb) = HeartbeatPayload::deserialize(data) {
                    log_heartbeat_rx(&hb);
                    update_routing_table_from_conn(conn, &hb, routing_table).await;
                } else {
                    println!(
                        "[central] Notification ({} bytes) failed to deserialize",
                        data.len()
                    );
                }
            }
        },
    )
    .await;

    Ok(())
}

/// Helper: update routing table from a connection's peer address and heartbeat
async fn update_routing_table_from_conn<P: PacketPool>(
    conn: &Connection<'_, P>,
    hb: &HeartbeatPayload,
    routing_table: &Mutex<NoopRawMutex, RoutingTable>,
) {
    let peer_bd_addr = conn.peer_address();
    let mac = peer_bd_addr.raw();
    let mut mac_arr = [0u8; 6];
    mac_arr.copy_from_slice(mac);
    let transport = TransportAddr {
        addr_type: 0, // BLE
        addr: mac_arr,
    };

    let mut table = routing_table.lock().await;
    table.update_peer(hb, transport, Instant::now().as_ticks());
    println!("  -> Routing table updated ({} peers)", table.peers.len());
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

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
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&short_addr[0..6]);
    mac[5] |= 0xC0;
    Address::random(mac)
}
