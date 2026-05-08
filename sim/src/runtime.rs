use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};

use embassy_executor::Spawner;
use embassy_futures::join::{join, join5};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use rand::{RngCore, SeedableRng as _};

use routing_core::behavior::run_heartbeat_loop;
use routing_core::crypto::identity::NodeIdentity;
use routing_core::routing::table::RoutingTable;

use crate::medium::SimMedium;
use crate::message_task;
use crate::network::{SimInitiator, SimNodeInfo, SimResponder};
use crate::scenario::{self, ScenarioId};
use crate::store_forward::{self, StoreForwardState};
use crate::sim_state::{SimCommand, SimConfig, TuiState, DEFAULT_NODES, MAX_NODES};
use crate::{behavior, command_task, snapshot_task};

const DEFAULT_SIM_SEED: u64 = 0xC0FFE_BABE;

async fn run_node(
    node_idx: usize,
    identity: &'static NodeIdentity,
    routing_table: &'static AsyncMutex<CriticalSectionRawMutex, RoutingTable>,
    uptime: &'static AsyncMutex<CriticalSectionRawMutex, u32>,
    medium: &'static SimMedium,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
    sim_config: Arc<Mutex<SimConfig>>,
    tui_state: Arc<Mutex<TuiState>>,
    store_forward_state: Arc<Mutex<StoreForwardState>>,
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
            Arc::clone(&store_forward_state),
            Arc::clone(&tui_state),
        ),
        behavior::run_initiator_loop_dynamic(
            node_idx,
            &mut initiator,
            identity,
            routing_table,
            uptime,
            Arc::clone(&sim_config),
            Arc::clone(&store_forward_state),
            Arc::clone(&tui_state),
        ),
        run_heartbeat_loop(uptime, routing_table),
        message_task::run_message_loop(
            node_idx,
            medium,
            routing_table,
            all_nodes,
            Arc::clone(&sim_config),
            Arc::clone(&tui_state),
            Arc::clone(&store_forward_state),
        ),
        message_task::run_sensor_loop(node_idx, medium, all_nodes, sim_config, tui_state),
    )
    .await;
}

#[embassy_executor::task(pool_size = 8)]
async fn embassy_main(
    identities: &'static [NodeIdentity; MAX_NODES],
    node_infos: &'static [SimNodeInfo; MAX_NODES],
    routing_tables: &'static [AsyncMutex<CriticalSectionRawMutex, RoutingTable>; MAX_NODES],
    uptimes: &'static [AsyncMutex<CriticalSectionRawMutex, u32>; MAX_NODES],
    medium: &'static SimMedium,
    tui_state: Arc<Mutex<TuiState>>,
    sim_config: Arc<Mutex<SimConfig>>,
    cmd_rx: Arc<Mutex<std::sync::mpsc::Receiver<SimCommand>>>,
    store_forward_state: Arc<Mutex<StoreForwardState>>,
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
                Arc::clone(&store_forward_state),
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
                    Arc::clone(&tui_state),
                    routing_tables,
                    uptimes,
                    Arc::clone(&store_forward_state),
                ),
            ),
            store_forward::run_store_forward_maintenance(
                store_forward_state,
                Arc::clone(&tui_state),
            ),
        ),
    )
    .await;
}

pub struct SimRuntime {
    pub tui_state: Arc<Mutex<TuiState>>,
    pub sim_config: Arc<Mutex<SimConfig>>,
    pub cmd_tx: Sender<SimCommand>,
    pub identities: &'static [NodeIdentity; MAX_NODES],
    pub node_infos: &'static [SimNodeInfo; MAX_NODES],
    pub routing_tables: &'static [AsyncMutex<CriticalSectionRawMutex, RoutingTable>; MAX_NODES],
    pub uptimes: &'static [AsyncMutex<CriticalSectionRawMutex, u32>; MAX_NODES],
    pub store_forward_state: Arc<Mutex<StoreForwardState>>,
}

impl SimRuntime {
    pub fn from_scenario(id: ScenarioId) -> Self {
        Self::start(scenario::build_config(id))
    }

    pub fn start(initial_config: SimConfig) -> Self {
        let tui_state = Arc::new(Mutex::new(TuiState::default()));
        let sim_config = Arc::new(Mutex::new(initial_config));
        let (cmd_tx, cmd_rx) = mpsc::channel::<SimCommand>();
        let cmd_rx = Arc::new(Mutex::new(cmd_rx));
        let store_forward_state = Arc::new(Mutex::new(StoreForwardState::default()));

        let mut rng = rand::rngs::SmallRng::seed_from_u64(DEFAULT_SIM_SEED);

        let identities: &'static [NodeIdentity; MAX_NODES] =
            Box::leak(Box::new(core::array::from_fn(|_| {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                NodeIdentity::from_bytes(&seed)
            })));

        let node_infos: &'static [SimNodeInfo; MAX_NODES] =
            Box::leak(Box::new(core::array::from_fn(|i| {
                let short_addr = *identities[i].short_addr();
                let mut mac = [0u8; 6];
                mac[0] = i as u8;
                mac[1..6].copy_from_slice(&short_addr[1..6]);
                SimNodeInfo { short_addr, mac }
            })));

        {
            let mut state = tui_state.lock().unwrap();
            state.node_short_addrs = core::array::from_fn(|i| node_infos[i].short_addr);
            for i in 0..MAX_NODES {
                state.nodes[i].short_addr = state.node_short_addrs[i];
            }
        }

        let routing_tables: &'static [AsyncMutex<CriticalSectionRawMutex, RoutingTable>;
                     MAX_NODES] = Box::leak(Box::new(core::array::from_fn(|i| {
            AsyncMutex::new(RoutingTable::new(*identities[i].short_addr()))
        })));

        let uptimes: &'static [AsyncMutex<CriticalSectionRawMutex, u32>; MAX_NODES] =
            Box::leak(Box::new(core::array::from_fn(|_| AsyncMutex::new(0u32))));

        let medium: &'static SimMedium = Box::leak(Box::new(SimMedium::new()));

        let tui_state_bg = Arc::clone(&tui_state);
        let sim_config_bg = Arc::clone(&sim_config);
        let cmd_rx_bg = Arc::clone(&cmd_rx);
        let store_forward_bg = Arc::clone(&store_forward_state);

        std::thread::Builder::new()
            .name("embassy".to_string())
            .spawn(move || {
                let executor: &'static mut embassy_executor::Executor =
                    Box::leak(Box::new(embassy_executor::Executor::new()));
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
                        store_forward_bg,
                    ));
                });
            })
            .expect("failed to spawn embassy thread");

        Self {
            tui_state,
            sim_config,
            cmd_tx,
            identities,
            node_infos,
            routing_tables,
            uptimes,
            store_forward_state,
        }
    }

    pub fn log_startup(&self) {
        log::info!(
            "Constellation Simulator — {} nodes ({} active at start)",
            MAX_NODES,
            DEFAULT_NODES
        );
        for (i, info) in self.node_infos.iter().enumerate() {
            log::info!("Node {}: short_addr={:02x?}", i, &info.short_addr[..4]);
        }
    }
}
