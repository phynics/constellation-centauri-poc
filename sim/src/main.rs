//! Constellation mesh simulator with interactive TUI.
//!
//! Embassy tasks run on a **background thread**.  The ratatui TUI runs on the
//! **main thread**.  They share state via two `Arc<Mutex<T>>` objects:
//!
//! - `TuiState`  — written by the snapshot task (1 Hz), read by the TUI renderer.
//! - `SimConfig` — written by the TUI (key presses), read by network adapters.
//!
//! A `std::sync::mpsc` channel carries `SimCommand`s from the TUI to a
//! dispatcher task in the embassy executor.
//!
//! Run with:
//!   cargo run -p sim

use std::sync::{Arc, Mutex};

use embassy_executor::Spawner;
use embassy_futures::join::{join, join5};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use static_cell::StaticCell;

use rand::{RngCore, SeedableRng as _};

use routing_core::behavior::run_heartbeat_loop;
use routing_core::crypto::identity::NodeIdentity;
use routing_core::routing::table::RoutingTable;

mod behavior;
mod command_task;
mod medium;
mod message_task;
mod network;
mod scenario;
mod sim_state;
mod snapshot_task;
mod tui;
mod tui_logger;

use medium::SimMedium;
use network::{SimInitiator, SimNodeInfo, SimResponder};
use sim_state::{SimCommand, SimConfig, TuiState, DEFAULT_NODES, MAX_NODES};

// =============================================================================
// Static storage — allocated once, accessible for the program lifetime.
// =============================================================================

static MEDIUM: StaticCell<SimMedium> = StaticCell::new();
static IDENTITIES: StaticCell<[NodeIdentity; MAX_NODES]> = StaticCell::new();
static NODE_INFOS: StaticCell<[SimNodeInfo; MAX_NODES]> = StaticCell::new();
static ROUTING_TABLES: StaticCell<[AsyncMutex<CriticalSectionRawMutex, RoutingTable>; MAX_NODES]> =
    StaticCell::new();
static UPTIMES: StaticCell<[AsyncMutex<CriticalSectionRawMutex, u32>; MAX_NODES]> =
    StaticCell::new();

// =============================================================================
// Per-node combined behavior task
// =============================================================================

async fn run_node(
    node_idx: usize,
    identity: &'static NodeIdentity,
    routing_table: &'static AsyncMutex<CriticalSectionRawMutex, RoutingTable>,
    uptime: &'static AsyncMutex<CriticalSectionRawMutex, u32>,
    medium: &'static SimMedium,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
    sim_config: Arc<Mutex<SimConfig>>,
    tui_state: Arc<Mutex<TuiState>>,
) {
    let mut responder = SimResponder::new(node_idx, medium, all_nodes, Arc::clone(&sim_config));
    let mut initiator = SimInitiator::new(node_idx, medium, all_nodes, Arc::clone(&sim_config));

    join5(
        behavior::run_responder_loop_dynamic(
            node_idx,
            &mut responder,
            identity,
            routing_table,
            uptime,
            Arc::clone(&sim_config),
        ),
        behavior::run_initiator_loop_dynamic(
            node_idx,
            &mut initiator,
            identity,
            routing_table,
            uptime,
            Arc::clone(&sim_config),
        ),
        run_heartbeat_loop(uptime, routing_table),
        message_task::run_message_loop(
            node_idx,
            medium,
            routing_table,
            all_nodes,
            Arc::clone(&sim_config),
            Arc::clone(&tui_state),
        ),
        message_task::run_sensor_loop(node_idx, medium, all_nodes, sim_config, tui_state),
    )
    .await;
}

// =============================================================================
// Top-level embassy task (spawned on the background thread)
// =============================================================================

#[embassy_executor::task]
async fn embassy_main(
    identities: &'static [NodeIdentity; MAX_NODES],
    node_infos: &'static [SimNodeInfo; MAX_NODES],
    routing_tables: &'static [AsyncMutex<CriticalSectionRawMutex, RoutingTable>; MAX_NODES],
    uptimes: &'static [AsyncMutex<CriticalSectionRawMutex, u32>; MAX_NODES],
    medium: &'static SimMedium,
    tui_state: Arc<Mutex<TuiState>>,
    sim_config: Arc<Mutex<SimConfig>>,
    cmd_rx: Arc<Mutex<std::sync::mpsc::Receiver<SimCommand>>>,
) {
    macro_rules! node {
        ($i:expr) => {
            run_node(
                $i,
                &identities[$i],
                &routing_tables[$i],
                &uptimes[$i],
                medium,
                node_infos,
                Arc::clone(&sim_config),
                Arc::clone(&tui_state),
            )
        };
    }

    join(
        join(
            join(
                join5(node!(0), node!(1), node!(2), node!(3), node!(4)),
                join5(node!(5), node!(6), node!(7), node!(8), node!(9)),
            ),
            join(
                join5(node!(10), node!(11), node!(12), node!(13), node!(14)),
                join5(node!(15), node!(16), node!(17), node!(18), node!(19)),
            ),
        ),
        join(
            snapshot_task::run_snapshot_loop(
                routing_tables,
                uptimes,
                identities,
                Arc::clone(&sim_config),
                Arc::clone(&tui_state),
            ),
            command_task::run_command_loop(
                cmd_rx,
                medium,
                node_infos,
                sim_config,
                tui_state,
                routing_tables,
                uptimes,
            ),
        ),
    )
    .await;
}

// =============================================================================
// Entry point
// =============================================================================

fn main() {
    tui_logger::init(log::LevelFilter::Info);

    log::info!(
        "Constellation Simulator — {} nodes ({} active at start)",
        MAX_NODES,
        DEFAULT_NODES
    );

    // ── Shared state ──────────────────────────────────────────────────────────
    let tui_state = Arc::new(Mutex::new(TuiState::default()));
    let sim_config = Arc::new(Mutex::new(scenario::build_config(
        scenario::default_scenario(),
    )));
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<SimCommand>();
    let cmd_rx = Arc::new(Mutex::new(cmd_rx));

    // ── Static storage ────────────────────────────────────────────────────────
    let mut rng = rand::rngs::SmallRng::seed_from_u64(0xC0FFE_BABE);

    let identities: &'static [NodeIdentity; MAX_NODES] =
        IDENTITIES.init(core::array::from_fn(|_| {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            NodeIdentity::from_bytes(&seed)
        }));

    let node_infos: &'static [SimNodeInfo; MAX_NODES] =
        NODE_INFOS.init(core::array::from_fn(|i| {
            let short_addr = *identities[i].short_addr();
            let mut mac = [0u8; 6];
            mac[0] = i as u8;
            mac[1..6].copy_from_slice(&short_addr[1..6]);
            log::info!("Node {}: short_addr={:02x?}", i, &short_addr[..4]);
            SimNodeInfo { short_addr, mac }
        }));

    {
        let mut state = tui_state.lock().unwrap();
        state.node_short_addrs = core::array::from_fn(|i| node_infos[i].short_addr);
        for i in 0..MAX_NODES {
            state.nodes[i].short_addr = state.node_short_addrs[i];
        }
    }

    let routing_tables: &'static [AsyncMutex<CriticalSectionRawMutex, RoutingTable>; MAX_NODES] =
        ROUTING_TABLES.init(core::array::from_fn(|i| {
            AsyncMutex::new(RoutingTable::new(*identities[i].short_addr()))
        }));

    let uptimes: &'static [AsyncMutex<CriticalSectionRawMutex, u32>; MAX_NODES] =
        UPTIMES.init(core::array::from_fn(|_| AsyncMutex::new(0u32)));

    let medium: &'static SimMedium = MEDIUM.init(SimMedium::new());

    // ── Embassy on background thread ──────────────────────────────────────────
    let tui_state_bg = Arc::clone(&tui_state);
    let sim_config_bg = Arc::clone(&sim_config);
    let cmd_rx_bg = Arc::clone(&cmd_rx);

    std::thread::Builder::new()
        .name("embassy".to_string())
        .spawn(move || {
            static EXECUTOR: StaticCell<embassy_executor::Executor> = StaticCell::new();
            let executor = EXECUTOR.init(embassy_executor::Executor::new());
            executor.run(|spawner: Spawner| {
                spawner.must_spawn(embassy_main(
                    identities,
                    node_infos,
                    routing_tables,
                    uptimes,
                    medium,
                    tui_state_bg,
                    sim_config_bg,
                    cmd_rx_bg,
                ));
            });
        })
        .expect("failed to spawn embassy thread");

    // ── TUI on main thread ────────────────────────────────────────────────────
    if let Err(e) = tui::run(tui_state, sim_config, cmd_tx) {
        eprintln!("TUI error: {e}");
        std::process::exit(1);
    }
}
