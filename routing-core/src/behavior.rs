//! Generic async behavior loops for mesh nodes.
//!
//! These functions contain the protocol logic (routing table updates, H2H
//! scheduling) but delegate all transport operations to the `H2hResponder`
//! and `H2hInitiator` traits. This makes them runnable identically in the
//! ESP32 firmware and in the `sim` crate.

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Instant, Timer};

use crate::config::{H2H_CYCLE_SECS, TICK_HZ};
use crate::crypto::identity::{short_addr_of, NodeIdentity, ShortAddr};
use crate::network::{DiscoveryEvent, H2hInitiator, H2hResponder, MAX_SCAN_RESULTS};
use crate::protocol::h2h::{self, H2hPayload};
use crate::routing::table::RoutingTable;
use crate::transport::TransportAddr;

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

/// Apply discovery scan results into the routing table using compact peer updates.
pub async fn apply_discovery_events<M: RawMutex>(
    routing_table: &Mutex<M, RoutingTable>,
    events: &heapless::Vec<DiscoveryEvent, MAX_SCAN_RESULTS>,
) {
    let mut table = routing_table.lock().await;
    let now = Instant::now().as_ticks();
    for event in events.iter() {
        let transport = TransportAddr::ble(event.mac);
        let is_new =
            table.update_peer_compact(event.short_addr, event.capabilities, transport, now);
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
    routing_table: &Mutex<M, RoutingTable>,
) -> heapless::Vec<(ShortAddr, [u8; 6]), 32> {
    let our_addr = *identity.short_addr();
    let table = routing_table.lock().await;
    let mut v = heapless::Vec::new();
    for peer in table.peers.iter() {
        if peer.transport_addr.addr != [0u8; 6] && h2h::is_initiator(&our_addr, &peer.short_addr) {
            let _ = v.push((peer.short_addr, peer.transport_addr.addr));
        }
    }
    v
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
    let peer_snapshots = collect_h2h_peer_snapshots(identity, routing_table).await;

    for (peer_addr, peer_mac) in peer_snapshots.iter() {
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
                log::info!(
                    "[central] H2H done with {:02x?}, peers={}",
                    &peer_addr[..4],
                    table.peers.len()
                );
            }
            Err(e) => {
                log::warn!("[central] H2H failed to {:02x?}: {:?}", &peer_addr[..4], e);
            }
        }
    }
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
                // Resolve partner's short_addr from pubkey (if sent) or MAC lookup.
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

                log::debug!(
                    "[periph] H2H from {:02x?}, partner={:02x?}",
                    inbound.peer_mac,
                    &partner_short[..4]
                );

                // Build response before updating routing table so the payload
                // reflects pre-exchange state (avoids echoing their own peers
                // back to them in the same exchange).
                let response = build_h2h_payload(
                    identity,
                    capabilities,
                    uptime,
                    routing_table,
                    &partner_short,
                )
                .await;

                // Update routing table with peer's payload.
                {
                    let transport = TransportAddr::ble(inbound.peer_mac);
                    let mut table = routing_table.lock().await;
                    table.update_peer_from_h2h(
                        &inbound.peer_payload,
                        partner_short,
                        transport,
                        Instant::now().as_ticks(),
                    );
                    log::info!("[periph] H2H done, peers={}", table.peers.len());
                }

                if let Err(e) = responder.send_h2h_response(&response).await {
                    log::warn!("[periph] send_h2h_response error: {:?}", e);
                }
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
    // Allow the peripheral task to start advertising before we scan.
    Timer::after(Duration::from_secs(3)).await;

    loop {
        let cycle_start = Instant::now();

        // ── Phase 1: Discovery scan ───────────────────────────────────────
        log::info!("[central] Discovery scan ({} ms)...", DISCOVERY_DURATION_MS);
        let events = initiator.scan(DISCOVERY_DURATION_MS).await;

        apply_discovery_events(routing_table, &events).await;

        // ── Phase 2: H2H connections ──────────────────────────────────────
        let our_addr = *identity.short_addr();
        let peer_snapshots = collect_h2h_peer_snapshots(identity, routing_table).await;

        if !peer_snapshots.is_empty() {
            log::info!(
                "[central] H2H cycle: {} peers to connect",
                peer_snapshots.len()
            );
        }

        for (peer_addr, peer_mac) in peer_snapshots.iter() {
            let offset = h2h::slot_offset(&our_addr, peer_addr);
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
                    log::info!(
                        "[central] H2H done with {:02x?}, peers={}",
                        &peer_addr[..4],
                        table.peers.len()
                    );
                }
                Err(e) => {
                    log::warn!("[central] H2H failed to {:02x?}: {:?}", &peer_addr[..4], e);
                }
            }
        }

        // ── Wait for next cycle ───────────────────────────────────────────
        let elapsed = Instant::now() - cycle_start;
        let cycle = Duration::from_secs(H2H_CYCLE_SECS);
        if elapsed < cycle {
            Timer::after(cycle - elapsed).await;
        }
    }
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
