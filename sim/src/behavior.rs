//! Simulator-side behavior adapters.
//!
//! Purpose: adapt shared routing-core behavior loops to simulator-owned runtime
//! state such as mutable scenario configuration and node toggles.
//!
//! Design decisions:
//! - Reuse shared behavior helpers instead of re-implementing protocol logic in
//!   the simulator.
//! - Let `SimConfig` drive host-only role toggles and experiment knobs.
use std::sync::{Arc, Mutex};

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex as AsyncMutex;
use embassy_time::{Duration, Instant, Timer};
use routing_core::behavior::{
    apply_discovery_events, build_h2h_payload, collect_h2h_peer_snapshots,
    respond_to_inbound_h2h_sync, run_initiator_store_forward_followups,
    run_responder_store_forward_followups, InboundH2hSyncError,
};
use routing_core::config::H2H_CYCLE_SECS;
use routing_core::crypto::identity::{NodeIdentity, ShortAddr};
use routing_core::network::{H2hInitiator, H2hResponder};
use routing_core::node::roles::Capabilities;
use routing_core::protocol::h2h;
use routing_core::routing::table::RoutingTable;
use routing_core::store_forward::StoreForwardObserver;

use crate::sim_state::{SimConfig, MAX_NODES};
use crate::sim_state::{TraceEventKind, TuiState};
use crate::store_forward::{SharedStoreForwardBackend, StoreForwardState};

const DISCOVERY_DURATION_MS: u64 = 7_000;

fn current_capabilities(sim_config: &Arc<Mutex<SimConfig>>, node_idx: usize) -> u16 {
    let cfg = sim_config.lock().unwrap();
    if node_idx < MAX_NODES {
        cfg.capabilities[node_idx]
    } else {
        0
    }
}

struct SimStoreForwardObserver {
    tui_state: Arc<Mutex<TuiState>>,
}

impl SimStoreForwardObserver {
    fn node_index_for(&self, addr: ShortAddr) -> usize {
        self.tui_state
            .lock()
            .unwrap()
            .node_short_addrs
            .iter()
            .position(|candidate| *candidate == addr)
            .unwrap_or(0)
    }
}

impl StoreForwardObserver for SimStoreForwardObserver {
    fn on_pending_announced(
        &mut self,
        trace_id: u64,
        router_addr: ShortAddr,
        lpn_addr: ShortAddr,
        pending_count: usize,
    ) {
        let router_idx = self.node_index_for(router_addr);
        let lpn_idx = self.node_index_for(lpn_addr);
        self.tui_state.lock().unwrap().push_trace_event(
            trace_id,
            router_idx,
            0,
            0,
            TraceEventKind::PendingAnnounced {
                count: pending_count,
            },
            format!(
                "router {} announced {} pending retained deliveries to LPN {}",
                router_idx, pending_count, lpn_idx
            ),
        );
    }

    fn on_delivery_confirmed(
        &mut self,
        trace_id: u64,
        router_addr: ShortAddr,
        lpn_addr: ShortAddr,
    ) {
        let router_idx = self.node_index_for(router_addr);
        let lpn_idx = self.node_index_for(lpn_addr);
        self.tui_state.lock().unwrap().push_trace_event(
            trace_id,
            router_idx,
            0,
            0,
            TraceEventKind::DeliveryConfirmed { lpn_node: lpn_idx },
            format!(
                "router {} received delayed-delivery confirmation from LPN {}",
                router_idx, lpn_idx
            ),
        );
    }

    fn on_delivered_from_store(
        &mut self,
        trace_id: u64,
        router_addr: ShortAddr,
        lpn_addr: ShortAddr,
    ) {
        let router_idx = self.node_index_for(router_addr);
        let lpn_idx = self.node_index_for(lpn_addr);
        let mut tui = self.tui_state.lock().unwrap();
        tui.push_trace_event(
            trace_id,
            lpn_idx,
            0,
            0,
            TraceEventKind::LpnWakeSync {
                router_node: router_idx,
            },
            format!(
                "LPN {} woke router {} for delayed-delivery sync",
                lpn_idx, router_idx
            ),
        );
        tui.push_trace_event(
            trace_id,
            lpn_idx,
            0,
            0,
            TraceEventKind::DeliveredFromStore {
                router_node: router_idx,
            },
            format!(
                "LPN {} received retained delivery from router {}",
                lpn_idx, router_idx
            ),
        );
        tui.mark_trace_delivered(trace_id);
    }
}

pub async fn run_responder_loop_dynamic<M, R>(
    node_idx: usize,
    responder: &mut R,
    identity: &NodeIdentity,
    routing_table: &AsyncMutex<M, RoutingTable>,
    uptime: &AsyncMutex<M, u32>,
    sim_config: Arc<Mutex<SimConfig>>,
    store_forward_state: Arc<Mutex<StoreForwardState>>,
    tui_state: Arc<Mutex<TuiState>>,
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
                let capabilities = current_capabilities(&sim_config, node_idx);
                let sync = match respond_to_inbound_h2h_sync(
                    responder,
                    &inbound,
                    identity,
                    capabilities,
                    uptime,
                    routing_table,
                )
                .await
                {
                    Ok(sync) => sync,
                    Err(InboundH2hSyncError::UnresolvedPartner) => {
                        log::warn!(
                            "[sim-periph] cannot resolve partner identity for transport {:?}; skipping session",
                            inbound.peer_transport_addr
                        );
                        let _ = responder.finish_h2h_session().await;
                        continue;
                    }
                    Err(InboundH2hSyncError::SendResponse(e)) => {
                        log::warn!("[sim-periph] send_h2h_response error: {:?}", e);
                        let _ = responder.finish_h2h_session().await;
                        continue;
                    }
                };
                let mut backend = SharedStoreForwardBackend::new(Arc::clone(&store_forward_state));
                let mut observer = SimStoreForwardObserver {
                    tui_state: Arc::clone(&tui_state),
                };
                let now_secs = tui_state.lock().unwrap().elapsed_secs;
                run_responder_store_forward_followups(
                    responder,
                    identity,
                    capabilities,
                    routing_table,
                    sync.partner_short,
                    sync.partner_capabilities,
                    &mut backend,
                    &mut observer,
                    now_secs,
                )
                .await;

                let _ = responder.finish_h2h_session().await;
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
    store_forward_state: Arc<Mutex<StoreForwardState>>,
    tui_state: Arc<Mutex<TuiState>>,
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
        let capabilities = current_capabilities(&sim_config, node_idx);
        let peer_snapshots =
            collect_h2h_peer_snapshots(identity, capabilities, routing_table).await;

        for (peer_addr, peer_transport_addr) in peer_snapshots.iter() {
            let offset = if Capabilities::is_low_power_endpoint_bits(capabilities) {
                0
            } else {
                h2h::slot_offset(&our_addr, peer_addr)
            };
            let target_time = cycle_start + Duration::from_secs(offset);

            if Instant::now() < target_time {
                Timer::at(target_time).await;
            }

            let payload =
                build_h2h_payload(identity, capabilities, uptime, routing_table, peer_addr).await;

            match initiator.initiate_h2h(*peer_transport_addr, &payload).await {
                Ok(peer_payload) => {
                    {
                        let mut table = routing_table.lock().await;
                        table.update_peer_from_h2h(
                            &peer_payload,
                            *peer_addr,
                            *peer_transport_addr,
                            Instant::now().as_ticks(),
                        );
                    }
                    let mut backend =
                        SharedStoreForwardBackend::new(Arc::clone(&store_forward_state));
                    let mut observer = SimStoreForwardObserver {
                        tui_state: Arc::clone(&tui_state),
                    };
                    let now_secs = tui_state.lock().unwrap().elapsed_secs;
                    run_initiator_store_forward_followups(
                        initiator,
                        identity,
                        capabilities,
                        routing_table,
                        *peer_addr,
                        &mut backend,
                        &mut observer,
                        now_secs,
                    )
                    .await;

                    let _ = initiator.finish_h2h_session().await;

                    // LPN wake cycles intentionally stop after the first
                    // successful router session. The candidate list is ranked
                    // so later peers are fallback targets, not additional sync
                    // partners for the same wake window.
                    if Capabilities::is_low_power_endpoint_bits(capabilities) {
                        break;
                    }
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
