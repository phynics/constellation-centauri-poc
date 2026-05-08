//! Embassy → TUI state bridge.
//!
//! Runs every second, snapshots all routing tables and uptimes, then writes
//! the result into `TuiState` using `try_lock` to avoid blocking the executor
//! when the TUI briefly holds the lock.

use std::sync::{Arc, Mutex};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use embassy_time::{Duration, Timer};

use routing_core::crypto::identity::NodeIdentity;
use routing_core::routing::table::RoutingTable;

use crate::sim_state::{NodeSnapshot, PeerSnapshot, SimConfig, TuiState, MAX_NODES};

pub async fn run_snapshot_loop(
    routing_tables: &'static [AsyncMutex<CriticalSectionRawMutex, RoutingTable>; MAX_NODES],
    uptimes: &'static [AsyncMutex<CriticalSectionRawMutex, u32>; MAX_NODES],
    identities: &'static [NodeIdentity; MAX_NODES],
    sim_config: Arc<Mutex<SimConfig>>,
    tui_state: Arc<Mutex<TuiState>>,
) -> ! {
    let mut elapsed = 0u32;
    loop {
        Timer::after(Duration::from_secs(1)).await;
        elapsed += 1;

        let (n_active, node_types, capabilities) = {
            let cfg = sim_config.lock().unwrap();
            let types: [crate::sim_state::NodeType; MAX_NODES] =
                core::array::from_fn(|i| cfg.node_types[i]);
            let capabilities: [u16; MAX_NODES] = core::array::from_fn(|i| cfg.capabilities[i]);
            (cfg.n_active, types, capabilities)
        };

        let mut snapshots: [NodeSnapshot; MAX_NODES] =
            core::array::from_fn(|_| NodeSnapshot::default());

        for i in 0..MAX_NODES {
            let short_addr = *identities[i].short_addr();

            if i >= n_active {
                snapshots[i].active = false;
                snapshots[i].short_addr = short_addr;
                continue;
            }

            let uptime_secs = *uptimes[i].lock().await;

            let rt = routing_tables[i].lock().await;
            let peers = rt
                .peers
                .iter()
                .map(|e| PeerSnapshot {
                    short_addr: e.short_addr,
                    trust: e.trust,
                    hop_count: e.hop_count,
                })
                .collect();

            snapshots[i] = NodeSnapshot {
                active: true,
                short_addr,
                uptime_secs,
                capabilities: capabilities[i],
                node_type: node_types[i],
                peers,
            };
        }

        // Write snapshot — skip this tick if TUI holds the lock.
        if let Ok(mut state) = tui_state.try_lock() {
            state.elapsed_secs = elapsed;
            state.nodes = snapshots;
        }
    }
}
