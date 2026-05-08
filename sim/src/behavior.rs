//! Simulator-specific behavior loops.
//!
//! These wrap the shared routing-core behavior helpers but fetch node
//! capabilities from `SimConfig` at runtime, so scenario switches can change
//! advertised roles without restarting the simulator.

use std::sync::{Arc, Mutex};

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use embassy_time::{Duration, Instant, Timer};

use routing_core::behavior::{
    apply_discovery_events, build_h2h_payload, collect_h2h_peer_snapshots,
};
use routing_core::config::H2H_CYCLE_SECS;
use routing_core::crypto::identity::{short_addr_of, NodeIdentity};
use routing_core::network::{H2hInitiator, H2hResponder};
use routing_core::protocol::h2h;
use routing_core::routing::table::RoutingTable;
use routing_core::transport::TransportAddr;

use crate::sim_state::{SimConfig, MAX_NODES};

const DISCOVERY_DURATION_MS: u64 = 7_000;

fn current_capabilities(sim_config: &Arc<Mutex<SimConfig>>, node_idx: usize) -> u16 {
    let cfg = sim_config.lock().unwrap();
    if node_idx < MAX_NODES {
        cfg.capabilities[node_idx]
    } else {
        0
    }
}

pub async fn run_responder_loop_dynamic<M, R>(
    node_idx: usize,
    responder: &mut R,
    identity: &NodeIdentity,
    routing_table: &AsyncMutex<M, RoutingTable>,
    uptime: &AsyncMutex<M, u32>,
    sim_config: Arc<Mutex<SimConfig>>,
) -> !
where
    M: RawMutex,
    R: H2hResponder,
{
    let addr_bytes = identity.short_addr();
    let jitter_ms = u16::from_le_bytes([addr_bytes[0], addr_bytes[1]]) % 2048;
    Timer::after(Duration::from_millis(jitter_ms as u64)).await;

    loop {
        match responder.receive_h2h().await {
            Ok(inbound) => {
                let partner_short = match inbound.peer_payload.full_pubkey {
                    Some(pk) => short_addr_of(&pk),
                    None => {
                        let table = routing_table.lock().await;
                        table
                            .peers
                            .iter()
                            .find(|p| p.transport_addr.addr == inbound.peer_mac)
                            .map(|p| p.short_addr)
                            .unwrap_or([0u8; 8])
                    }
                };

                let capabilities = current_capabilities(&sim_config, node_idx);
                let response = build_h2h_payload(
                    identity,
                    capabilities,
                    uptime,
                    routing_table,
                    &partner_short,
                )
                .await;

                {
                    let transport = TransportAddr::ble(inbound.peer_mac);
                    let mut table = routing_table.lock().await;
                    table.update_peer_from_h2h(
                        &inbound.peer_payload,
                        partner_short,
                        transport,
                        Instant::now().as_ticks(),
                    );
                }

                if let Err(e) = responder.send_h2h_response(&response).await {
                    log::warn!("[sim-periph] send_h2h_response error: {:?}", e);
                }
            }
            Err(e) => {
                log::warn!("[sim-periph] receive_h2h error: {:?}", e);
            }
        }
    }
}

pub async fn run_initiator_loop_dynamic<M, I>(
    node_idx: usize,
    initiator: &mut I,
    identity: &NodeIdentity,
    routing_table: &AsyncMutex<M, RoutingTable>,
    uptime: &AsyncMutex<M, u32>,
    sim_config: Arc<Mutex<SimConfig>>,
) -> !
where
    M: RawMutex,
    I: H2hInitiator,
{
    Timer::after(Duration::from_secs(3)).await;

    loop {
        let cycle_start = Instant::now();

        let events = initiator.scan(DISCOVERY_DURATION_MS).await;
        apply_discovery_events(routing_table, &events).await;

        let our_addr = *identity.short_addr();
        let peer_snapshots = collect_h2h_peer_snapshots(identity, routing_table).await;

        for (peer_addr, peer_mac) in peer_snapshots.iter() {
            let offset = h2h::slot_offset(&our_addr, peer_addr);
            let target_time = cycle_start + Duration::from_secs(offset);

            if Instant::now() < target_time {
                Timer::at(target_time).await;
            }

            let capabilities = current_capabilities(&sim_config, node_idx);
            let payload =
                build_h2h_payload(identity, capabilities, uptime, routing_table, peer_addr).await;

            match initiator.initiate_h2h(*peer_mac, &payload).await {
                Ok(peer_payload) => {
                    let transport = TransportAddr::ble(*peer_mac);
                    let mut table = routing_table.lock().await;
                    table.update_peer_from_h2h(
                        &peer_payload,
                        *peer_addr,
                        transport,
                        Instant::now().as_ticks(),
                    );
                }
                Err(e) => {
                    log::warn!(
                        "[sim-central] H2H failed to {:02x?}: {:?}",
                        &peer_addr[..4],
                        e
                    );
                }
            }
        }

        let elapsed = Instant::now() - cycle_start;
        let cycle = Duration::from_secs(H2H_CYCLE_SECS);
        if elapsed < cycle {
            Timer::after(cycle - elapsed).await;
        }
    }
}
