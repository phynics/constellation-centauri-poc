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

esp_bootloader_esp_idf::esp_app_desc!();

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use embassy_executor::Spawner;
use embassy_futures::join::join4;
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

use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeCreateConn, LeSetScanEnable,
    LeSetScanParams,
};
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};

pub mod node;
pub mod transport;

use routing_core::behavior::{run_heartbeat_loop, run_initiator_loop, run_responder_loop};
use routing_core::crypto::identity::NodeIdentity;
use routing_core::node::roles::Capabilities;
use routing_core::routing::table::RoutingTable;

use transport::ble_network::{parse_discovery_from_adv, BleInitiator, BleResponder, DiscoveryInfo};

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

/// Scan handler delivers discovered peers into this channel.
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
    let connector =
        BleConnector::new(bluetooth, Default::default()).expect("Failed to create BLE connector");
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

    let mut ble_responder =
        BleResponder::new(peripheral, &stack, *identity.short_addr(), capabilities.0);

    let mut ble_initiator = BleInitiator::new(central, &stack, address, discovery_rx);

    println!("Ready — advertising for discovery + H2H exchange");

    let _ = join4(
        ble_runner_task(runner, &scan_handler),
        run_responder_loop(
            &mut ble_responder,
            &identity,
            capabilities.0,
            routing_table,
            uptime,
        ),
        run_initiator_loop(
            &mut ble_initiator,
            &identity,
            capabilities.0,
            routing_table,
            uptime,
        ),
        run_heartbeat_loop(uptime, routing_table),
    )
    .await;
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
