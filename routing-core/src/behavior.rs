//! Generic async behavior loops for mesh nodes.
//!
//! These functions contain the protocol logic (routing table updates, H2H
//! scheduling) but delegate all transport operations to the `H2hResponder`
//! and `H2hInitiator` traits. This makes them runnable identically in the
//! ESP32 firmware and in the `sim` crate.

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Instant, Timer};
use sha2::{Digest, Sha256};

use crate::config::{H2H_CYCLE_SECS, STORE_FORWARD_BACKUP_ROUTERS, TICK_HZ};
use crate::crypto::identity::{short_addr_of, NodeIdentity, ShortAddr};
use crate::network::{DiscoveryEvent, H2hInitiator, H2hResponder, MAX_SCAN_RESULTS};
use crate::node::roles::Capabilities;
use crate::protocol::h2h::{self, H2hFrame, H2hPayload, H2H_ACK_IDS_MAX};
use crate::routing::table::RoutingTable;
use crate::store_forward::{
    collect_known_store_routers, StoreForwardBackend, StoreForwardObserver,
};
use crate::transport::TransportAddr;

pub struct InboundH2hSync {
    pub partner_short: ShortAddr,
    pub partner_capabilities: u16,
}

#[derive(Debug)]
pub enum InboundH2hSyncError {
    UnresolvedPartner,
    SendResponse(crate::network::NetworkError),
}

#[allow(async_fn_in_trait)]
pub trait InitiatorCycleObserver<I: H2hInitiator> {
    async fn before_cycle(&mut self, _initiator: &mut I) {}
    async fn after_peer(&mut self, _initiator: &mut I) {}
}

pub struct NoopInitiatorCycleObserver;

impl<I: H2hInitiator> InitiatorCycleObserver<I> for NoopInitiatorCycleObserver {}

/// Deterministic placement score for choosing backup routers for a low-power
/// endpoint. Unlike the primary router choice, which is intentionally local and
/// quality-driven, backup placement must be independently derivable by any
/// router that knows the destination LPN and a candidate router address.
pub fn backup_router_score_for_lpn(lpn_addr: &ShortAddr, router_addr: &ShortAddr) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(lpn_addr);
    hasher.update(router_addr);
    let digest = hasher.finalize();
    u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

pub fn sort_backup_routers_for_lpn<T, F>(lpn_addr: &ShortAddr, routers: &mut [T], router_addr: F)
where
    F: Fn(&T) -> ShortAddr,
{
    routers.sort_unstable_by(|a, b| {
        backup_router_score_for_lpn(lpn_addr, &router_addr(b))
            .cmp(&backup_router_score_for_lpn(lpn_addr, &router_addr(a)))
            .then_with(|| router_addr(a).cmp(&router_addr(b)))
    });
}

// ── Discovery scan duration ───────────────────────────────────────────────────

/// How long to scan for new peers at the start of each H2H cycle (ms).
const DISCOVERY_DURATION_MS: u64 = 7_000;

// ── Shared payload builder ────────────────────────────────────────────────────

/// Build an H2H payload from local state, tailored for a specific partner.
///
/// - Omits our pubkey if the partner already has it.
/// - Uses recency-weighted sampling filtered to exclude peers the partner
///   already knows.
pub async fn build_h2h_payload<M: RawMutex>(
    identity: &NodeIdentity,
    capabilities: u16,
    uptime: &Mutex<M, u32>,
    routing_table: &Mutex<M, RoutingTable>,
    partner_addr: &ShortAddr,
) -> H2hPayload {
    let now = Instant::now().as_ticks();
    let uptime_secs = *uptime.lock().await;

    let (peers, peer_count, include_pubkey) = {
        let table = routing_table.lock().await;

        let partner_knows_us = table
            .find_peer(partner_addr)
            .map(|e| e.pubkey != [0u8; 32])
            .unwrap_or(false);

        let addr_bytes = identity.short_addr();
        let addr_u32 =
            u32::from_le_bytes([addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]]);
        let seed = addr_u32 ^ (now as u32);

        let (peers, count) = table.top_peers_for(partner_addr, now, seed);
        (peers, count, !partner_knows_us)
    };

    H2hPayload {
        full_pubkey: if include_pubkey {
            Some(identity.pubkey())
        } else {
            None
        },
        capabilities,
        uptime_secs,
        peers,
        peer_count,
    }
}

/// Resolve the short address for an inbound H2H partner.
///
/// Prefer the short address derived from the peer's full pubkey when present.
/// If the peer omitted its pubkey, fall back to an existing routing-table entry
/// matched by transport address. Returns `None` when the peer cannot be
/// resolved safely; callers should skip the session rather than inventing a
/// synthetic address.
pub async fn resolve_inbound_partner_short_addr<M: RawMutex>(
    inbound: &crate::network::InboundH2h,
    routing_table: &Mutex<M, RoutingTable>,
) -> Option<ShortAddr> {
    match inbound.peer_payload.full_pubkey {
        Some(pk) => Some(short_addr_of(&pk)),
        None => {
            let table = routing_table.lock().await;
            table
                .peers
                .iter()
                .find(|p| p.transport_addr == inbound.peer_transport_addr)
                .map(|p| p.short_addr)
        }
    }
}

pub async fn respond_to_inbound_h2h_sync<M: RawMutex, R: H2hResponder>(
    responder: &mut R,
    inbound: &crate::network::InboundH2h,
    identity: &NodeIdentity,
    capabilities: u16,
    uptime: &Mutex<M, u32>,
    routing_table: &Mutex<M, RoutingTable>,
) -> Result<InboundH2hSync, InboundH2hSyncError> {
    let Some(partner_short) = resolve_inbound_partner_short_addr(inbound, routing_table).await
    else {
        return Err(InboundH2hSyncError::UnresolvedPartner);
    };

    let response = build_h2h_payload(
        identity,
        capabilities,
        uptime,
        routing_table,
        &partner_short,
    )
    .await;

    {
        let mut table = routing_table.lock().await;
        table.update_peer_from_h2h(
            &inbound.peer_payload,
            partner_short,
            inbound.peer_transport_addr,
            Instant::now().as_ticks(),
        );
    }

    responder
        .send_h2h_response(&response)
        .await
        .map_err(InboundH2hSyncError::SendResponse)?;

    Ok(InboundH2hSync {
        partner_short,
        partner_capabilities: inbound.peer_payload.capabilities,
    })
}

/// Apply discovery scan results into the routing table using compact peer updates.
pub async fn apply_discovery_events<M: RawMutex>(
    routing_table: &Mutex<M, RoutingTable>,
    events: &heapless::Vec<DiscoveryEvent, MAX_SCAN_RESULTS>,
) {
    let mut table = routing_table.lock().await;
    let now = Instant::now().as_ticks();
    for event in events.iter() {
        let is_new = table.update_peer_compact(
            event.short_addr,
            event.capabilities,
            event.transport_addr,
            now,
        );
        if is_new {
            log::info!(
                "[central] New peer {:02x?} ({} total)",
                &event.short_addr[..4],
                table.peers.len()
            );
        }
    }
}

/// Collect current H2H connection candidates for which this node is the initiator.
pub async fn collect_h2h_peer_snapshots<M: RawMutex>(
    identity: &NodeIdentity,
    capabilities: u16,
    routing_table: &Mutex<M, RoutingTable>,
) -> heapless::Vec<(ShortAddr, TransportAddr), 32> {
    let our_addr = *identity.short_addr();
    let table = routing_table.lock().await;
    let mut v = heapless::Vec::new();

    let is_low_power_endpoint = Capabilities::is_low_power_endpoint_bits(capabilities);

    // Low-power endpoints use an explicit wake/uplink model instead of trying
    // to maintain eager pair ownership with every router they can hear.
    //
    // We still rank store-capable routers deterministically so the first router
    // remains the preferred wake target. However, we now return the full ranked
    // list rather than truncating to one peer. That gives the initiator loop a
    // natural fallback path: if the preferred router is down, the LPN can wake
    // the next-best reachable router in the same cycle without inventing a
    // second connection policy just for delayed delivery.
    if is_low_power_endpoint {
        let mut routers: heapless::Vec<(ShortAddr, TransportAddr, u8, u64, bool), 32> =
            heapless::Vec::new();

        for peer in table.peers.iter() {
            if peer.transport_addr.is_empty() || (peer.capabilities & Capabilities::ROUTE == 0) {
                continue;
            }

            let candidate = (
                peer.short_addr,
                peer.transport_addr,
                peer.trust,
                peer.last_seen_ticks,
                Capabilities::is_store_router_bits(peer.capabilities),
            );

            let _ = routers.push(candidate);
        }

        let mut primary_idx = None;
        for idx in 0..routers.len() {
            let candidate = routers[idx];
            let should_replace = match primary_idx {
                None => true,
                Some(best_idx) => {
                    let best: (ShortAddr, TransportAddr, u8, u64, bool) = routers[best_idx];
                    candidate.2 > best.2
                        || (candidate.2 == best.2 && candidate.3 > best.3)
                        || (candidate.2 == best.2 && candidate.3 == best.3 && candidate.0 < best.0)
                }
            };
            if should_replace {
                primary_idx = Some(idx);
            }
        }

        if let Some(primary_idx) = primary_idx {
            let primary = routers.swap_remove(primary_idx);
            // Primary stays quality-driven from the LPN perspective, but all
            // remaining routers are ordered by deterministic distance/score from
            // the LPN address. That keeps fallback placement stable across the
            // mesh even when the LPN's preferred router drops out.
            routers.sort_unstable_by(|a, b| {
                b.4.cmp(&a.4).then_with(|| {
                    backup_router_score_for_lpn(&our_addr, &b.0)
                        .cmp(&backup_router_score_for_lpn(&our_addr, &a.0))
                        .then_with(|| a.0.cmp(&b.0))
                })
            });
            let _ = v.push((primary.0, primary.1));
        }

        for (peer_short, peer_transport, ..) in routers.into_iter() {
            let _ = v.push((peer_short, peer_transport));
        }

        return v;
    }

    for peer in table.peers.iter() {
        if peer.transport_addr.is_empty() {
            continue;
        }

        // Full routing participants should not proactively H2H into low-power
        // endpoint nodes. They can still learn those endpoints from discovery,
        // while the endpoint initiates uplink H2H when it needs richer state.
        let peer_is_low_power_endpoint =
            Capabilities::is_low_power_endpoint_bits(peer.capabilities);
        if peer_is_low_power_endpoint {
            continue;
        }

        if h2h::is_initiator(&our_addr, &peer.short_addr) {
            let _ = v.push((peer.short_addr, peer.transport_addr));
        }
    }
    v
}

pub fn is_backup_router_for_lpn(
    lpn_addr: &ShortAddr,
    candidate_router: &ShortAddr,
    known_store_routers: &[ShortAddr],
) -> bool {
    let mut routers: heapless::Vec<ShortAddr, 32> = heapless::Vec::new();
    for router in known_store_routers {
        if !routers.iter().any(|existing| existing == router) {
            let _ = routers.push(*router);
        }
    }
    sort_backup_routers_for_lpn(lpn_addr, routers.as_mut_slice(), |addr| *addr);
    routers
        .iter()
        .take(STORE_FORWARD_BACKUP_ROUTERS)
        .any(|router| router == candidate_router)
}

/// Perform immediate H2H exchanges for the current known initiator-side peers.
///
/// This skips slot waiting and is intended for deterministic testing / host-side
/// orchestration. Runtime scheduling remains in `run_initiator_loop`.
pub async fn run_initiator_h2h_once<M, I>(
    initiator: &mut I,
    identity: &NodeIdentity,
    capabilities: u16,
    routing_table: &Mutex<M, RoutingTable>,
    uptime: &Mutex<M, u32>,
) where
    M: RawMutex,
    I: H2hInitiator,
{
    let peer_snapshots = collect_h2h_peer_snapshots(identity, capabilities, routing_table).await;

    for (peer_addr, peer_transport_addr) in peer_snapshots.iter() {
        let payload =
            build_h2h_payload(identity, capabilities, uptime, routing_table, peer_addr).await;

        match initiator.initiate_h2h(*peer_transport_addr, &payload).await {
            Ok(peer_payload) => {
                let mut table = routing_table.lock().await;
                table.update_peer_from_h2h(
                    &peer_payload,
                    *peer_addr,
                    *peer_transport_addr,
                    Instant::now().as_ticks(),
                );
                log::info!(
                    "[central] H2H done with {:02x?}, peers={}",
                    &peer_addr[..4],
                    table.peers.len()
                );
                let _ = initiator.finish_h2h_session().await;
            }
            Err(e) => {
                log::warn!("[central] H2H failed to {:02x?}: {:?}", &peer_addr[..4], e);
                let _ = initiator.finish_h2h_session().await;
            }
        }
    }
}

pub async fn run_initiator_loop_with_observer<M, I, O>(
    initiator: &mut I,
    identity: &NodeIdentity,
    capabilities: u16,
    routing_table: &Mutex<M, RoutingTable>,
    uptime: &Mutex<M, u32>,
    observer: &mut O,
) -> !
where
    M: RawMutex,
    I: H2hInitiator,
    O: InitiatorCycleObserver<I>,
{
    Timer::after(Duration::from_secs(3)).await;

    loop {
        observer.before_cycle(initiator).await;

        let cycle_start = Instant::now();

        log::info!("[central] Discovery scan ({} ms)...", DISCOVERY_DURATION_MS);
        let events = initiator.scan(DISCOVERY_DURATION_MS).await;
        apply_discovery_events(routing_table, &events).await;

        let our_addr = *identity.short_addr();
        let peer_snapshots =
            collect_h2h_peer_snapshots(identity, capabilities, routing_table).await;

        if !peer_snapshots.is_empty() {
            log::info!(
                "[central] H2H cycle: {} peers to connect",
                peer_snapshots.len()
            );
        }

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

            log::info!(
                "[central] H2H → {:02x?} (slot {}s)",
                &peer_addr[..4],
                offset
            );

            let payload =
                build_h2h_payload(identity, capabilities, uptime, routing_table, peer_addr).await;

            match initiator.initiate_h2h(*peer_transport_addr, &payload).await {
                Ok(peer_payload) => {
                    let mut table = routing_table.lock().await;
                    table.update_peer_from_h2h(
                        &peer_payload,
                        *peer_addr,
                        *peer_transport_addr,
                        Instant::now().as_ticks(),
                    );
                    log::info!(
                        "[central] H2H done with {:02x?}, peers={}",
                        &peer_addr[..4],
                        table.peers.len()
                    );
                    let _ = initiator.finish_h2h_session().await;
                    observer.after_peer(initiator).await;

                    if Capabilities::is_low_power_endpoint_bits(capabilities) {
                        break;
                    }
                }
                Err(e) => {
                    log::warn!("[central] H2H failed to {:02x?}: {:?}", &peer_addr[..4], e);
                    let _ = initiator.finish_h2h_session().await;
                    observer.after_peer(initiator).await;
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

pub async fn drain_responder_h2h_frames_until_done<R: H2hResponder>(responder: &mut R) {
    loop {
        match responder.receive_h2h_frame().await {
            Ok(H2hFrame::SessionDone) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

pub async fn drain_initiator_h2h_frames_until_done<I: H2hInitiator>(initiator: &mut I) {
    loop {
        match initiator.receive_h2h_frame().await {
            Ok(H2hFrame::SessionDone) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

pub async fn run_responder_store_forward_followups<M, R, S, O>(
    responder: &mut R,
    identity: &NodeIdentity,
    local_capabilities: u16,
    routing_table: &Mutex<M, RoutingTable>,
    partner_short: ShortAddr,
    partner_capabilities: u16,
    backend: &mut S,
    observer: &mut O,
    now_secs: u32,
) where
    M: RawMutex,
    R: H2hResponder,
    S: StoreForwardBackend,
    O: StoreForwardObserver,
{
    let local_addr = *identity.short_addr();
    if Capabilities::is_low_power_endpoint_bits(partner_capabilities) {
        let pending = backend.pending_for_delivery(local_addr, partner_short);
        let summary = H2hFrame::DeliverySummary {
            pending_count: pending.len().min(u8::MAX as usize) as u8,
            preferred_router: true,
        };

        if responder.send_h2h_frame(&summary).await.is_ok() {
            for entry in pending.iter() {
                observer.on_pending_announced(
                    entry.trace_id,
                    local_addr,
                    partner_short,
                    pending.len(),
                );
            }
        }

        let mut acked = heapless::Vec::<u64, 8>::new();
        for entry in pending.iter() {
            let frame = H2hFrame::DeliveryData {
                trace_id: entry.trace_id,
                message_id: entry.message_id,
                source_addr: entry.source_addr,
                destination_addr: entry.destination_addr,
                body: entry.body.clone(),
            };

            if responder.send_h2h_frame(&frame).await.is_err() {
                break;
            }

            match responder.receive_h2h_frame().await {
                Ok(H2hFrame::DeliveryAck { trace_ids }) => {
                    for trace_id in trace_ids {
                        let _ = acked.push(trace_id);
                        observer.on_delivery_confirmed(trace_id, local_addr, partner_short);
                    }
                }
                Ok(H2hFrame::SessionDone) | Err(_) => break,
                Ok(_) => {}
            }
        }

        if !acked.is_empty() {
            backend.ack_delivered(local_addr, acked.as_slice());
        }

        let _ = responder.send_h2h_frame(&H2hFrame::SessionDone).await;
        return;
    }

    if !(Capabilities::is_store_router_bits(local_capabilities)
        && Capabilities::is_store_router_bits(partner_capabilities))
    {
        return;
    }

    let tombstones = backend.tombstones();
    if !tombstones.is_empty() {
        let mut trace_ids = heapless::Vec::new();
        for trace_id in tombstones.iter().take(H2H_ACK_IDS_MAX) {
            let _ = trace_ids.push(*trace_id);
        }
        let _ = responder
            .send_h2h_frame(&H2hFrame::RetentionTombstone { trace_ids })
            .await;
    }

    let replication_candidates = backend.replication_candidates(local_addr);
    let known_store_routers = {
        let table = routing_table.lock().await;
        collect_known_store_routers(*identity.short_addr(), local_capabilities, &table)
    };

    for entry in replication_candidates {
        if !is_backup_router_for_lpn(
            &entry.destination_addr,
            &partner_short,
            known_store_routers.as_slice(),
        ) {
            continue;
        }

        let frame = H2hFrame::RetentionReplica {
            trace_id: entry.trace_id,
            message_id: entry.message_id,
            source_addr: entry.source_addr,
            destination_addr: entry.destination_addr,
            owner_router_addr: entry.owner_router_addr,
            body: entry.body.clone(),
        };

        if responder.send_h2h_frame(&frame).await.is_err() {
            break;
        }

        match responder.receive_h2h_frame().await {
            Ok(H2hFrame::RetentionAck { .. }) => {}
            Ok(H2hFrame::SessionDone) | Err(_) => break,
            Ok(_) => {}
        }
    }

    let _ = responder.send_h2h_frame(&H2hFrame::SessionDone).await;

    loop {
        match responder.receive_h2h_frame().await {
            Ok(H2hFrame::RetentionTombstone { trace_ids }) => {
                backend.apply_tombstones(trace_ids.as_slice());
            }
            Ok(H2hFrame::RetentionReplica {
                trace_id,
                message_id,
                source_addr,
                destination_addr,
                owner_router_addr,
                body,
            }) => {
                let retained = backend.retain_replica(crate::store_forward::RetainedMessage {
                    trace_id,
                    message_id,
                    source_addr,
                    destination_addr,
                    holder_addr: local_addr,
                    owner_router_addr,
                    body,
                    enqueued_at_secs: now_secs,
                    announced: false,
                });

                if retained {
                    let mut trace_ids = heapless::Vec::new();
                    let _ = trace_ids.push(trace_id);
                    let _ = responder
                        .send_h2h_frame(&H2hFrame::RetentionAck { trace_ids })
                        .await;
                }
            }
            Ok(H2hFrame::SessionDone) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

pub async fn run_initiator_store_forward_followups<M, I, S, O>(
    initiator: &mut I,
    identity: &NodeIdentity,
    local_capabilities: u16,
    routing_table: &Mutex<M, RoutingTable>,
    peer_addr: ShortAddr,
    backend: &mut S,
    observer: &mut O,
    now_secs: u32,
) where
    M: RawMutex,
    I: H2hInitiator,
    S: StoreForwardBackend,
    O: StoreForwardObserver,
{
    let local_addr = *identity.short_addr();
    if Capabilities::is_low_power_endpoint_bits(local_capabilities) {
        loop {
            match initiator.receive_h2h_frame().await {
                Ok(H2hFrame::DeliverySummary { pending_count, .. }) => {
                    if pending_count == 0 {
                        continue;
                    }
                }
                Ok(H2hFrame::DeliveryData { trace_id, .. }) => {
                    observer.on_delivered_from_store(trace_id, peer_addr, local_addr);
                    let mut trace_ids = heapless::Vec::new();
                    let _ = trace_ids.push(trace_id);
                    let _ = initiator
                        .send_h2h_frame(&H2hFrame::DeliveryAck { trace_ids })
                        .await;
                }
                Ok(H2hFrame::SessionDone) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        return;
    }

    if !Capabilities::is_store_router_bits(local_capabilities) {
        return;
    }

    loop {
        match initiator.receive_h2h_frame().await {
            Ok(H2hFrame::RetentionTombstone { trace_ids }) => {
                backend.apply_tombstones(trace_ids.as_slice());
            }
            Ok(H2hFrame::RetentionReplica {
                trace_id,
                message_id,
                source_addr,
                destination_addr,
                owner_router_addr,
                body,
            }) => {
                let retained = backend.retain_replica(crate::store_forward::RetainedMessage {
                    trace_id,
                    message_id,
                    source_addr,
                    destination_addr,
                    holder_addr: local_addr,
                    owner_router_addr,
                    body,
                    enqueued_at_secs: now_secs,
                    announced: false,
                });

                if retained {
                    let mut trace_ids = heapless::Vec::new();
                    let _ = trace_ids.push(trace_id);
                    let _ = initiator
                        .send_h2h_frame(&H2hFrame::RetentionAck { trace_ids })
                        .await;
                }
            }
            Ok(H2hFrame::SessionDone) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let known_store_routers = {
        let table = routing_table.lock().await;
        collect_known_store_routers(*identity.short_addr(), local_capabilities, &table)
    };

    let tombstones = backend.tombstones();
    if !tombstones.is_empty() {
        let mut trace_ids = heapless::Vec::new();
        for trace_id in tombstones.iter().take(H2H_ACK_IDS_MAX) {
            let _ = trace_ids.push(*trace_id);
        }
        let _ = initiator
            .send_h2h_frame(&H2hFrame::RetentionTombstone { trace_ids })
            .await;
    }

    let replication_candidates = backend.replication_candidates(local_addr);
    for entry in replication_candidates {
        if !is_backup_router_for_lpn(
            &entry.destination_addr,
            &peer_addr,
            known_store_routers.as_slice(),
        ) {
            continue;
        }

        let frame = H2hFrame::RetentionReplica {
            trace_id: entry.trace_id,
            message_id: entry.message_id,
            source_addr: entry.source_addr,
            destination_addr: entry.destination_addr,
            owner_router_addr: entry.owner_router_addr,
            body: entry.body.clone(),
        };

        if initiator.send_h2h_frame(&frame).await.is_err() {
            break;
        }

        match initiator.receive_h2h_frame().await {
            Ok(H2hFrame::RetentionAck { .. }) => {}
            Ok(H2hFrame::SessionDone) | Err(_) => break,
            Ok(_) => {}
        }
    }

    let _ = initiator.send_h2h_frame(&H2hFrame::SessionDone).await;
}

// ── Responder loop ────────────────────────────────────────────────────────────

/// Runs the peripheral (responder) H2H loop forever.
///
/// Waits for an inbound H2H connection, receives the peer's payload, updates
/// the routing table, builds a tailored response, and sends it — all without
/// BLE-specific code.
pub async fn run_responder_loop<M, R>(
    responder: &mut R,
    identity: &NodeIdentity,
    capabilities: u16,
    routing_table: &Mutex<M, RoutingTable>,
    uptime: &Mutex<M, u32>,
) -> !
where
    M: RawMutex,
    R: H2hResponder,
{
    // Startup jitter: prevents all nodes from advertising simultaneously.
    let addr_bytes = identity.short_addr();
    let jitter_ms = u16::from_le_bytes([addr_bytes[0], addr_bytes[1]]) % 2048;
    Timer::after(Duration::from_millis(jitter_ms as u64)).await;

    loop {
        match responder.receive_h2h().await {
            Ok(inbound) => {
                match respond_to_inbound_h2h_sync(
                    responder,
                    &inbound,
                    identity,
                    capabilities,
                    uptime,
                    routing_table,
                )
                .await
                {
                    Ok(sync) => {
                        log::debug!(
                            "[periph] H2H from {:02x?}, partner={:02x?}",
                            &inbound.peer_transport_addr.addr
                                [..inbound.peer_transport_addr.len as usize],
                            &sync.partner_short[..4]
                        );
                        let table = routing_table.lock().await;
                        log::info!("[periph] H2H done, peers={}", table.peers.len());
                    }
                    Err(InboundH2hSyncError::UnresolvedPartner) => {
                        log::warn!(
                            "[periph] cannot resolve partner identity for transport {:?}; skipping session",
                            inbound.peer_transport_addr
                        );
                    }
                    Err(InboundH2hSyncError::SendResponse(e)) => {
                        log::warn!("[periph] send_h2h_response error: {:?}", e);
                    }
                }

                let _ = responder.finish_h2h_session().await;
            }
            Err(e) => {
                log::warn!("[periph] receive_h2h error: {:?}", e);
            }
        }
    }
}

// ── Initiator loop ────────────────────────────────────────────────────────────

/// Runs the central (initiator) H2H loop forever.
///
/// Phase 1: Discovery scan — collects neighbor advertisements, updates the
///          routing table with compact (no full pubkey) entries.
/// Phase 2: H2H connections — for each peer where we are the initiator,
///          connects at the deterministic slot time and performs a full
///          H2H exchange.
pub async fn run_initiator_loop<M, I>(
    initiator: &mut I,
    identity: &NodeIdentity,
    capabilities: u16,
    routing_table: &Mutex<M, RoutingTable>,
    uptime: &Mutex<M, u32>,
) -> !
where
    M: RawMutex,
    I: H2hInitiator,
{
    let mut observer = NoopInitiatorCycleObserver;
    run_initiator_loop_with_observer(
        initiator,
        identity,
        capabilities,
        routing_table,
        uptime,
        &mut observer,
    )
    .await
}

// ── Heartbeat loop ────────────────────────────────────────────────────────────

/// Increments the uptime counter and applies routing table decay every 5 s.
pub async fn run_heartbeat_loop<M>(
    uptime: &Mutex<M, u32>,
    routing_table: &Mutex<M, RoutingTable>,
) -> !
where
    M: RawMutex,
{
    loop {
        Timer::after(Duration::from_secs(5)).await;

        let up = {
            let mut u = uptime.lock().await;
            *u = u.saturating_add(5);
            *u
        };

        let peers = {
            let mut table = routing_table.lock().await;
            let max_age = H2H_CYCLE_SECS * 3 * TICK_HZ;
            table.decay(Instant::now().as_ticks(), max_age);
            table.peers.len()
        };

        log::info!("[heartbeat] Uptime: {}s, peers: {}", up, peers);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        backup_router_score_for_lpn, is_backup_router_for_lpn, sort_backup_routers_for_lpn,
    };

    #[test]
    fn backup_router_scoring_is_deterministic() {
        let lpn = [0x11; 8];
        let router = [0x22; 8];
        assert_eq!(
            backup_router_score_for_lpn(&lpn, &router),
            backup_router_score_for_lpn(&lpn, &router)
        );
    }

    #[test]
    fn backup_subset_is_derived_from_lpn_identity() {
        let lpn = [0x42; 8];
        let mut routers = [[0x01; 8], [0x02; 8], [0x03; 8], [0x04; 8]];
        sort_backup_routers_for_lpn(&lpn, &mut routers, |addr| *addr);

        assert!(is_backup_router_for_lpn(&lpn, &routers[0], &routers));
        assert!(is_backup_router_for_lpn(&lpn, &routers[1], &routers));
        assert!(!is_backup_router_for_lpn(&lpn, &routers[3], &routers));
    }
}
