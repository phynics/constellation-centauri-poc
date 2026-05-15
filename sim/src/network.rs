//! `SimResponder` and `SimInitiator` — in-process implementations of the
//! `H2hResponder` / `H2hInitiator` traits using `SimMedium` channels.
//!
//! Topology and packet-drop behaviour are driven by `SimConfig` at runtime,
//! so the TUI can toggle links and adjust drop probabilities on the fly.

use std::sync::{Arc, Mutex};

use embassy_time::{Duration, Timer};
use heapless::Vec;
use rand::{Rng as _, SeedableRng as _};

use routing_core::crypto::identity::ONBOARDING_READY_NETWORK_ADDR;
use routing_core::network::{
    DiscoveryEvent, H2hInitiator, H2hResponder, InboundH2h, NetworkError, MAX_SCAN_RESULTS,
};
use routing_core::node::roles::Capabilities;
use routing_core::protocol::h2h::{H2hFrame, H2hPayload};
use routing_core::transport::TransportAddr;

use crate::medium::{
    deserialize_frame, deserialize_payload, serialize_frame, serialize_payload, SimH2hFrame,
    SimH2hRequest, SimH2hResponse, SimMedium,
};
use crate::sim_state::{SimConfig, MAX_NODES};

// ── Peer info shared across all sim nodes ─────────────────────────────────────

/// Static info about every simulated node, shared with all `SimInitiator`s.
pub struct SimNodeInfo {
    pub short_addr: [u8; 8],
    /// MAC used on the simulated medium.  Convention: `mac[0] = node_index`.
    pub mac: [u8; 6],
}

// ── SimResponder ──────────────────────────────────────────────────────────────

pub struct SimResponder {
    node_idx: usize,
    medium: &'static SimMedium,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
    sim_config: Arc<Mutex<SimConfig>>,
    pending_sender: Option<usize>,
}

impl SimResponder {
    pub fn new(
        node_idx: usize,
        medium: &'static SimMedium,
        all_nodes: &'static [SimNodeInfo; MAX_NODES],
        sim_config: Arc<Mutex<SimConfig>>,
    ) -> Self {
        Self {
            node_idx,
            medium,
            all_nodes,
            sim_config,
            pending_sender: None,
        }
    }
}

impl H2hResponder for SimResponder {
    async fn receive_h2h(&mut self) -> Result<InboundH2h, NetworkError> {
        let req = self.medium.h2h_req[self.node_idx].receive().await;

        let respond_h2h = {
            let cfg = self.sim_config.lock().unwrap();
            self.node_idx < cfg.n_active && cfg.node_behaviors[self.node_idx].respond_h2h
        };

        if !respond_h2h {
            self.medium.h2h_resp[req.sender_idx]
                .send(SimH2hResponse {
                    result: Err(NetworkError::RespondDisabled),
                })
                .await;
            return Err(NetworkError::RespondDisabled);
        }

        let peer_payload = deserialize_payload(&req.payload_bytes, req.payload_len)
            .ok_or(NetworkError::ProtocolError)?;

        let peer_transport_addr = TransportAddr::ble(self.all_nodes[req.sender_idx].mac);
        self.pending_sender = Some(req.sender_idx);

        Ok(InboundH2h {
            peer_transport_addr,
            peer_payload,
        })
    }

    async fn send_h2h_response(&mut self, payload: &H2hPayload) -> Result<(), NetworkError> {
        let sender_idx = self.pending_sender.ok_or(NetworkError::ProtocolError)?;

        let (bytes, len) = serialize_payload(payload).ok_or(NetworkError::ProtocolError)?;

        self.medium.h2h_resp[sender_idx]
            .send(SimH2hResponse {
                result: Ok((bytes, len)),
            })
            .await;

        Ok(())
    }

    async fn send_h2h_frame(&mut self, frame: &H2hFrame) -> Result<(), NetworkError> {
        let sender_idx = self.pending_sender.ok_or(NetworkError::ProtocolError)?;
        let (bytes, len) = serialize_frame(frame).ok_or(NetworkError::ProtocolError)?;

        self.medium.h2h_to_initiator[sender_idx]
            .send(SimH2hFrame {
                result: Ok((bytes, len)),
            })
            .await;

        Ok(())
    }

    async fn receive_h2h_frame(&mut self) -> Result<H2hFrame, NetworkError> {
        let sender_idx = self.pending_sender.ok_or(NetworkError::ProtocolError)?;
        let frame = self.medium.h2h_to_responder[self.node_idx].receive().await;
        let (bytes, len) = frame.result?;

        // The channel is per-responder node, but we still require that the
        // responder has an active peer recorded before accepting a frame.
        let _ = sender_idx;
        deserialize_frame(&bytes, len).ok_or(NetworkError::ProtocolError)
    }

    async fn finish_h2h_session(&mut self) -> Result<(), NetworkError> {
        self.pending_sender = None;
        Ok(())
    }
}

// ── SimInitiator ──────────────────────────────────────────────────────────────

pub struct SimInitiator {
    node_idx: usize,
    medium: &'static SimMedium,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
    sim_config: Arc<Mutex<SimConfig>>,
    scan_round: usize,
    pending_peer_idx: Option<usize>,
}

impl SimInitiator {
    pub fn new(
        node_idx: usize,
        medium: &'static SimMedium,
        all_nodes: &'static [SimNodeInfo; MAX_NODES],
        sim_config: Arc<Mutex<SimConfig>>,
    ) -> Self {
        Self {
            node_idx,
            medium,
            all_nodes,
            sim_config,
            scan_round: 0,
            pending_peer_idx: None,
        }
    }
}

impl H2hInitiator for SimInitiator {
    async fn scan(&mut self, duration_ms: u64) -> Vec<DiscoveryEvent, MAX_SCAN_RESULTS> {
        // Simulate scan latency.
        Timer::after(Duration::from_millis(duration_ms)).await;

        let config = self.sim_config.lock().unwrap();
        let self_caps = config.capabilities[self.node_idx];
        let low_power_endpoint = is_low_power_endpoint(self_caps);

        // Inactive nodes don't scan. Low-power endpoints are allowed to scan
        // for uplink routers even when general scan behavior is disabled.
        if self.node_idx >= config.n_active {
            return Vec::new();
        }
        if !config.node_behaviors[self.node_idx].scan && !low_power_endpoint {
            return Vec::new();
        }

        let mut candidate_indices = std::vec::Vec::new();
        for (i, node) in self.all_nodes.iter().enumerate() {
            if i == self.node_idx || i >= config.n_active {
                continue;
            }
            if !config.node_behaviors[i].advertise {
                continue;
            }
            if low_power_endpoint && config.capabilities[i] & Capabilities::ROUTE == 0 {
                continue;
            }
            if !config.link_enabled[self.node_idx][i] {
                continue;
            }
            // Apply drop_prob to advertising packets too, so a dropped link
            // stops refreshing last_seen_ticks and trust decays naturally.
            let drop = config.drop_prob[self.node_idx][i];
            if drop > 0 && rand::thread_rng().gen_range(0u8..100) < drop {
                continue;
            }
            let _ = node;
            candidate_indices.push(i);
        }

        let mut results = Vec::new();
        if candidate_indices.len() <= MAX_SCAN_RESULTS {
            for idx in candidate_indices {
                let node = &self.all_nodes[idx];
                let _ = results.push(DiscoveryEvent {
                    short_addr: node.short_addr,
                    capabilities: config.capabilities[idx],
                    network_addr: ONBOARDING_READY_NETWORK_ADDR,
                    transport_addr: TransportAddr::ble(node.mac),
                });
            }
            return results;
        }

        let mut rng = rand::rngs::SmallRng::seed_from_u64(
            ((self.node_idx as u64) << 32) ^ self.scan_round as u64 ^ 0x51CA_515Au64,
        );
        self.scan_round = self.scan_round.wrapping_add(1);

        for _ in 0..MAX_SCAN_RESULTS {
            let pick = rng.gen_range(0..candidate_indices.len());
            let idx = candidate_indices.swap_remove(pick);
            let node = &self.all_nodes[idx];
            let _ = results.push(DiscoveryEvent {
                short_addr: node.short_addr,
                capabilities: config.capabilities[idx],
                network_addr: ONBOARDING_READY_NETWORK_ADDR,
                transport_addr: TransportAddr::ble(node.mac),
            });
        }
        results
    }

    async fn initiate_h2h(
        &mut self,
        peer_transport_addr: TransportAddr,
        our_payload: &H2hPayload,
    ) -> Result<H2hPayload, NetworkError> {
        let peer_mac = peer_transport_addr
            .as_ble_mac()
            .ok_or(NetworkError::ProtocolError)?;
        // Convention: mac[0] = node_index in the simulator.
        let peer_idx = peer_mac[0] as usize;
        if peer_idx >= MAX_NODES {
            return Err(NetworkError::ConnectionFailed);
        }

        // Check config: inactive peer or simulated packet drop.
        {
            let config = self.sim_config.lock().unwrap();
            let self_caps = config.capabilities[self.node_idx];
            let peer_caps = config.capabilities[peer_idx];
            let allow_low_power_uplink =
                is_low_power_endpoint(self_caps) && peer_caps & Capabilities::ROUTE != 0;

            if self.node_idx >= config.n_active || peer_idx >= config.n_active {
                return Err(NetworkError::PeerInactive);
            }
            if !config.node_behaviors[self.node_idx].initiate_h2h && !allow_low_power_uplink {
                return Err(NetworkError::InitiateDisabled);
            }
            if !config.node_behaviors[peer_idx].respond_h2h {
                return Err(NetworkError::RespondDisabled);
            }
            if !config.link_enabled[self.node_idx][peer_idx] {
                return Err(NetworkError::LinkDisabled);
            }
            let drop = config.drop_prob[self.node_idx][peer_idx];
            if drop > 0 && rand::thread_rng().gen_range(0u8..100) < drop {
                return Err(NetworkError::DropRejected);
            }
        }

        let (bytes, len) = serialize_payload(our_payload).ok_or(NetworkError::ProtocolError)?;

        // Push H2H request into peer's inbox.
        self.medium.h2h_req[peer_idx]
            .send(SimH2hRequest {
                sender_idx: self.node_idx,
                payload_bytes: bytes,
                payload_len: len,
            })
            .await;

        // Wait for response in our own response slot.
        let response = self.medium.h2h_resp[self.node_idx].receive().await;

        let (resp_bytes, resp_len) = response.result?;
        self.pending_peer_idx = Some(peer_idx);
        deserialize_payload(&resp_bytes, resp_len).ok_or(NetworkError::ProtocolError)
    }

    async fn send_h2h_frame(&mut self, frame: &H2hFrame) -> Result<(), NetworkError> {
        let peer_idx = self.pending_peer_idx.ok_or(NetworkError::ProtocolError)?;
        let (bytes, len) = serialize_frame(frame).ok_or(NetworkError::ProtocolError)?;

        self.medium.h2h_to_responder[peer_idx]
            .send(SimH2hFrame {
                result: Ok((bytes, len)),
            })
            .await;

        Ok(())
    }

    async fn receive_h2h_frame(&mut self) -> Result<H2hFrame, NetworkError> {
        self.pending_peer_idx.ok_or(NetworkError::ProtocolError)?;
        let frame = self.medium.h2h_to_initiator[self.node_idx].receive().await;
        let (bytes, len) = frame.result?;
        deserialize_frame(&bytes, len).ok_or(NetworkError::ProtocolError)
    }

    async fn finish_h2h_session(&mut self) -> Result<(), NetworkError> {
        self.pending_peer_idx = None;
        Ok(())
    }
}

fn is_low_power_endpoint(capabilities: u16) -> bool {
    Capabilities::is_low_power_endpoint_bits(capabilities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::mutex::Mutex as AsyncMutex;
    use pollster::block_on;
    use routing_core::behavior::{
        apply_discovery_events, collect_h2h_peer_snapshots, run_initiator_h2h_once,
    };
    use routing_core::crypto::identity::NodeIdentity;
    use routing_core::network::{H2hInitiator, H2hResponder};
    use routing_core::protocol::h2h::{H2hPayload, PeerInfo};
    use routing_core::routing::table::{RoutingTable, TRUST_DIRECT, TRUST_INDIRECT};
    use routing_core::transport::TransportAddr;
    use std::sync::{Arc, Mutex};

    use crate::medium::SimMedium;

    fn node_info(idx: usize) -> SimNodeInfo {
        let mut short_addr = [0u8; 8];
        short_addr[0] = idx as u8 + 1;

        let mut mac = [0u8; 6];
        mac[0] = idx as u8;
        mac[1] = idx as u8 + 0x10;

        SimNodeInfo { short_addr, mac }
    }

    fn test_nodes() -> &'static [SimNodeInfo; MAX_NODES] {
        Box::leak(Box::new(core::array::from_fn(node_info)))
    }

    fn test_medium() -> &'static SimMedium {
        Box::leak(Box::new(SimMedium::new()))
    }

    fn test_identities() -> &'static [NodeIdentity; MAX_NODES] {
        Box::leak(Box::new(core::array::from_fn(|i| {
            let mut secret = [0u8; 32];
            secret[0] = i as u8 + 1;
            secret[31] = 0xA0 + i as u8;
            NodeIdentity::from_bytes(&secret)
        })))
    }

    fn nodes_from_identities(
        identities: &'static [NodeIdentity; MAX_NODES],
    ) -> &'static [SimNodeInfo; MAX_NODES] {
        Box::leak(Box::new(core::array::from_fn(|i| {
            let short_addr = *identities[i].short_addr();
            let mut mac = [0u8; 6];
            mac[0] = i as u8;
            mac[1..6].copy_from_slice(&short_addr[1..6]);
            SimNodeInfo { short_addr, mac }
        })))
    }

    fn test_routing_tables(
        identities: &'static [NodeIdentity; MAX_NODES],
    ) -> &'static [AsyncMutex<CriticalSectionRawMutex, RoutingTable>; MAX_NODES] {
        Box::leak(Box::new(core::array::from_fn(|i| {
            AsyncMutex::new(RoutingTable::new(*identities[i].short_addr()))
        })))
    }

    fn test_uptimes() -> &'static [AsyncMutex<CriticalSectionRawMutex, u32>; MAX_NODES] {
        Box::leak(Box::new(core::array::from_fn(|_| AsyncMutex::new(0u32))))
    }

    fn test_config(n_active: usize) -> Arc<Mutex<SimConfig>> {
        let mut cfg = SimConfig::default();
        cfg.n_active = n_active;
        Arc::new(Mutex::new(cfg))
    }

    fn test_payload(seed: u8) -> H2hPayload {
        const NONE: Option<PeerInfo> = None;
        let mut peers = [NONE; routing_core::config::H2H_MAX_PEER_ENTRIES];
        peers[0] = Some(PeerInfo {
            pubkey: [seed.wrapping_add(1); 32],
            capabilities: 0x2200 + seed as u16,
            hop_count: 1,
        });

        H2hPayload {
            full_pubkey: Some([seed; 32]),
            capabilities: 0x1100 + seed as u16,
            uptime_secs: 77 + seed as u32,
            peers,
            peer_count: 1,
        }
    }

    fn initiator_responder_pair(
        nodes: &'static [SimNodeInfo; MAX_NODES],
        a: usize,
        b: usize,
    ) -> (usize, usize) {
        if nodes[a].short_addr < nodes[b].short_addr {
            (a, b)
        } else {
            (b, a)
        }
    }

    fn endpoint_router_pair(
        nodes: &'static [SimNodeInfo; MAX_NODES],
        a: usize,
        b: usize,
    ) -> (usize, usize) {
        if nodes[a].short_addr > nodes[b].short_addr {
            (a, b)
        } else {
            (b, a)
        }
    }

    #[test]
    fn scan_returns_active_linked_peers_only() {
        let medium = test_medium();
        let nodes = test_nodes();
        let config = test_config(3);
        let mut initiator = SimInitiator::new(0, medium, nodes, config);

        let results = block_on(initiator.scan(0));

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].short_addr, nodes[1].short_addr);
        assert_eq!(results[1].short_addr, nodes[2].short_addr);
        assert!(results
            .iter()
            .all(|event| event.transport_addr.as_ble_mac() != Some(nodes[0].mac)));
    }

    #[test]
    fn scan_returns_onboarding_ready_network_addr() {
        let medium = test_medium();
        let nodes = test_nodes();
        let config = test_config(3);
        let mut initiator = SimInitiator::new(0, medium, nodes, config);

        let results = block_on(initiator.scan(0));

        // Sim nodes don't model enrollment, so all advertise OnboardingReady
        assert!(results
            .iter()
            .all(|event| event.network_addr == ONBOARDING_READY_NETWORK_ADDR));
    }

    #[test]
    fn scan_excludes_link_disabled_peers() {
        let medium = test_medium();
        let nodes = test_nodes();
        let config = test_config(3);
        config.lock().unwrap().link_enabled[0][1] = false;

        let mut initiator = SimInitiator::new(0, medium, nodes, config);
        let results = block_on(initiator.scan(0));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].short_addr, nodes[2].short_addr);
    }

    #[test]
    fn scan_excludes_peers_when_drop_probability_is_100_percent() {
        let medium = test_medium();
        let nodes = test_nodes();
        let config = test_config(2);
        config.lock().unwrap().drop_prob[0][1] = 100;

        let mut initiator = SimInitiator::new(0, medium, nodes, config);
        let results = block_on(initiator.scan(0));

        assert!(results.is_empty());
    }

    #[test]
    fn initiate_h2h_fails_when_drop_probability_is_100_percent() {
        let medium = test_medium();
        let nodes = test_nodes();
        let config = test_config(2);
        config.lock().unwrap().drop_prob[0][1] = 100;

        let mut initiator = SimInitiator::new(0, medium, nodes, config);
        let result = block_on(initiator.initiate_h2h(TransportAddr::ble(nodes[1].mac), &test_payload(0x21)));

        assert!(matches!(result, Err(NetworkError::DropRejected)));
    }

    #[test]
    fn h2h_exchange_roundtrips_between_initiator_and_responder() {
        let medium = test_medium();
        let nodes = test_nodes();
        let config = test_config(2);

        let request_payload = test_payload(0x31);
        let response_payload = test_payload(0x41);
        let expected_response_pubkey = response_payload.full_pubkey;
        let expected_response_capabilities = response_payload.capabilities;
        let expected_response_uptime = response_payload.uptime_secs;
        let expected_response_peer_count = response_payload.peer_count;

        let responder_thread = std::thread::spawn({
            let config = Arc::clone(&config);
            move || {
                let mut responder = SimResponder::new(1, medium, nodes, config);
                block_on(async {
                    let inbound = responder.receive_h2h().await.unwrap();
                    assert_eq!(inbound.peer_transport_addr.as_ble_mac(), Some(nodes[0].mac));
                    assert_eq!(
                        inbound.peer_payload.full_pubkey,
                        request_payload.full_pubkey
                    );
                    assert_eq!(
                        inbound.peer_payload.capabilities,
                        request_payload.capabilities
                    );
                    assert_eq!(
                        inbound.peer_payload.uptime_secs,
                        request_payload.uptime_secs
                    );
                    responder
                        .send_h2h_response(&response_payload)
                        .await
                        .unwrap();
                });
            }
        });

        let mut initiator = SimInitiator::new(0, medium, nodes, config);
        let received = block_on(initiator.initiate_h2h(TransportAddr::ble(nodes[1].mac), &request_payload)).unwrap();

        responder_thread.join().unwrap();

        assert_eq!(received.full_pubkey, expected_response_pubkey);
        assert_eq!(received.capabilities, expected_response_capabilities);
        assert_eq!(received.uptime_secs, expected_response_uptime);
        assert_eq!(received.peer_count, expected_response_peer_count);
    }

    #[test]
    fn initiator_h2h_learns_indirect_peer_from_responder() {
        let medium = test_medium();
        let identities = test_identities();
        let nodes = nodes_from_identities(identities);
        let routing_tables = test_routing_tables(identities);
        let uptimes = test_uptimes();
        let config = test_config(3);
        {
            let (node_a, _node_b) = initiator_responder_pair(nodes, 0, 1);
            let node_c = 2usize;
            let mut cfg = config.lock().unwrap();
            cfg.link_enabled[node_a][node_c] = false;
            cfg.link_enabled[node_c][node_a] = false;
        }

        block_on(async {
            let (node_a, node_b) = initiator_responder_pair(nodes, 0, 1);
            let node_c = 2usize;

            {
                let mut b_table = routing_tables[node_b].lock().await;
                let inserted = b_table.peers.push(routing_core::routing::table::PeerEntry {
                    pubkey: identities[node_c].pubkey(),
                    short_addr: nodes[node_c].short_addr,
                    capabilities: config.lock().unwrap().capabilities[node_c],
                    bloom: routing_core::routing::bloom::BloomFilter::new(),
                    transport_addr: TransportAddr::ble(nodes[node_c].mac),
                    last_seen_ticks: 1,
                    hop_count: 0,
                    trust: TRUST_DIRECT,
                    learned_from: [0u8; 8],
                });
                assert!(inserted.is_ok());
            }

            let mut initiator = SimInitiator::new(node_a, medium, nodes, Arc::clone(&config));
            let mut responder = SimResponder::new(node_b, medium, nodes, Arc::clone(&config));

            let scan_results = initiator.scan(0).await;
            apply_discovery_events(&routing_tables[node_a], &scan_results).await;

            let response = routing_core::behavior::build_h2h_payload(
                &identities[node_b],
                {
                    let cfg = config.lock().unwrap();
                    cfg.capabilities[node_b]
                },
                &uptimes[node_b],
                &routing_tables[node_b],
                identities[node_a].short_addr(),
            )
            .await;

            let initiator_caps = {
                let cfg = config.lock().unwrap();
                cfg.capabilities[node_a]
            };

            let responder_thread = std::thread::spawn(move || {
                block_on(async {
                    let inbound = responder.receive_h2h().await.unwrap();
                    assert_eq!(inbound.peer_transport_addr.as_ble_mac(), Some(nodes[node_a].mac));
                    responder.send_h2h_response(&response).await.unwrap();
                });
            });

            run_initiator_h2h_once(
                &mut initiator,
                &identities[node_a],
                initiator_caps,
                &routing_tables[node_a],
                &uptimes[node_a],
            )
            .await;

            responder_thread.join().unwrap();

            let a_table = routing_tables[node_a].lock().await;
            let b_entry = a_table.find_peer(&nodes[node_b].short_addr).unwrap();
            assert_eq!(b_entry.trust, TRUST_DIRECT);

            let c_entry = a_table.find_peer(&nodes[node_c].short_addr).unwrap();
            assert_eq!(c_entry.trust, TRUST_INDIRECT);
            assert_eq!(c_entry.learned_from, nodes[node_b].short_addr);
            assert_eq!(c_entry.hop_count, 1);
        });
    }

    #[test]
    fn link_disable_and_reenable_changes_discovery_and_h2h_outcome() {
        let medium = test_medium();
        let identities = test_identities();
        let nodes = nodes_from_identities(identities);
        let routing_tables = test_routing_tables(identities);
        let uptimes = test_uptimes();
        let config = test_config(2);

        block_on(async {
            let (node_a, node_b) = initiator_responder_pair(nodes, 0, 1);

            let mut initiator = SimInitiator::new(node_a, medium, nodes, Arc::clone(&config));

            let first_scan = initiator.scan(0).await;
            assert_eq!(first_scan.len(), 1);
            apply_discovery_events(&routing_tables[node_a], &first_scan).await;

            {
                let table = routing_tables[node_a].lock().await;
                let b_entry = table.find_peer(&nodes[node_b].short_addr).unwrap();
                assert_eq!(b_entry.trust, TRUST_DIRECT);
                assert_eq!(b_entry.transport_addr.as_ble_mac(), Some(nodes[node_b].mac));
            }

            {
                let mut cfg = config.lock().unwrap();
                cfg.link_enabled[node_a][node_b] = false;
            }

            let disabled_scan = initiator.scan(0).await;
            assert!(disabled_scan.is_empty());

            let disabled_h2h = initiator
                .initiate_h2h(TransportAddr::ble(nodes[node_b].mac), &test_payload(0x55))
                .await;
            assert!(matches!(disabled_h2h, Err(NetworkError::LinkDisabled)));

            {
                let mut cfg = config.lock().unwrap();
                cfg.link_enabled[node_a][node_b] = true;
            }

            let reenabled_scan = initiator.scan(0).await;
            assert_eq!(reenabled_scan.len(), 1);
            apply_discovery_events(&routing_tables[node_a], &reenabled_scan).await;

            let response = routing_core::behavior::build_h2h_payload(
                &identities[node_b],
                {
                    let cfg = config.lock().unwrap();
                    cfg.capabilities[node_b]
                },
                &uptimes[node_b],
                &routing_tables[node_b],
                identities[node_a].short_addr(),
            )
            .await;

            let initiator_caps = {
                let cfg = config.lock().unwrap();
                cfg.capabilities[node_a]
            };

            let mut responder = SimResponder::new(node_b, medium, nodes, Arc::clone(&config));
            let responder_thread = std::thread::spawn(move || {
                block_on(async {
                    let inbound = responder.receive_h2h().await.unwrap();
                    assert_eq!(inbound.peer_transport_addr.as_ble_mac(), Some(nodes[node_a].mac));
                    responder.send_h2h_response(&response).await.unwrap();
                });
            });

            run_initiator_h2h_once(
                &mut initiator,
                &identities[node_a],
                initiator_caps,
                &routing_tables[node_a],
                &uptimes[node_a],
            )
            .await;

            responder_thread.join().unwrap();

            let table = routing_tables[node_a].lock().await;
            let b_entry = table.find_peer(&nodes[node_b].short_addr).unwrap();
            assert_eq!(b_entry.trust, TRUST_DIRECT);
            assert_eq!(b_entry.pubkey, identities[node_b].pubkey());
        });
    }

    #[test]
    fn scan_excludes_non_advertising_peers() {
        let medium = test_medium();
        let nodes = test_nodes();
        let config = test_config(2);
        config.lock().unwrap().node_behaviors[1].advertise = false;

        let mut initiator = SimInitiator::new(0, medium, nodes, config);
        let results = block_on(initiator.scan(0));

        assert!(results.is_empty());
    }

    #[test]
    fn scan_probabilistically_cycles_when_neighbors_exceed_result_capacity() {
        let medium = test_medium();
        let nodes = test_nodes();
        let config = test_config(MAX_NODES);

        let mut initiator = SimInitiator::new(0, medium, nodes, config);

        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let results = block_on(initiator.scan(0));
            assert_eq!(results.len(), MAX_SCAN_RESULTS);
            for event in results.iter() {
                seen.insert(event.transport_addr.as_ble_mac().unwrap()[0] as usize);
            }
        }

        // Node 0 scans 19 neighbors in a full 20-node topology; repeated scans
        // must eventually surface the highest-index peers instead of starving
        // them behind the result cap.
        assert!(seen.contains(&17));
        assert!(seen.contains(&18));
        assert!(seen.contains(&19));
    }

    #[test]
    fn low_power_endpoint_can_initiate_uplink_h2h_to_router_even_when_normal_initiation_is_disabled(
    ) {
        let medium = test_medium();
        let identities = test_identities();
        let nodes = nodes_from_identities(identities);
        let routing_tables = test_routing_tables(identities);
        let uptimes = test_uptimes();
        let config = test_config(2);

        block_on(async {
            let (endpoint, router) = endpoint_router_pair(nodes, 0, 1);
            {
                let mut cfg = config.lock().unwrap();
                cfg.capabilities[endpoint] = Capabilities::LOW_ENERGY | Capabilities::APPLICATION;
                cfg.capabilities[router] = Capabilities::ROUTE | Capabilities::STORE;
                cfg.node_behaviors[endpoint].scan = false;
                cfg.node_behaviors[endpoint].initiate_h2h = false;
                cfg.node_behaviors[router].respond_h2h = true;
            }

            let mut initiator = SimInitiator::new(endpoint, medium, nodes, Arc::clone(&config));
            let mut responder = SimResponder::new(router, medium, nodes, Arc::clone(&config));

            let scan_results = initiator.scan(0).await;
            assert_eq!(scan_results.len(), 1);
            assert_eq!(scan_results[0].short_addr, nodes[router].short_addr);
            apply_discovery_events(&routing_tables[endpoint], &scan_results).await;

            let endpoint_caps = {
                let cfg = config.lock().unwrap();
                cfg.capabilities[endpoint]
            };
            let candidates = collect_h2h_peer_snapshots(
                &identities[endpoint],
                endpoint_caps,
                &routing_tables[endpoint],
            )
            .await;
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].0, nodes[router].short_addr);

            let response = routing_core::behavior::build_h2h_payload(
                &identities[router],
                {
                    let cfg = config.lock().unwrap();
                    cfg.capabilities[router]
                },
                &uptimes[router],
                &routing_tables[router],
                identities[endpoint].short_addr(),
            )
            .await;

            let responder_thread = std::thread::spawn(move || {
                block_on(async {
                    let inbound = responder.receive_h2h().await.unwrap();
                    assert_eq!(inbound.peer_transport_addr.as_ble_mac(), Some(nodes[endpoint].mac));
                    responder.send_h2h_response(&response).await.unwrap();
                });
            });

            run_initiator_h2h_once(
                &mut initiator,
                &identities[endpoint],
                endpoint_caps,
                &routing_tables[endpoint],
                &uptimes[endpoint],
            )
            .await;

            responder_thread.join().unwrap();

            let table = routing_tables[endpoint].lock().await;
            let router_entry = table.find_peer(&nodes[router].short_addr).unwrap();
            assert_eq!(router_entry.trust, TRUST_DIRECT);
            assert_eq!(router_entry.transport_addr.as_ble_mac(), Some(nodes[router].mac));
        });
    }

    #[test]
    fn router_does_not_schedule_h2h_into_low_power_endpoint() {
        let identities = test_identities();
        let nodes = nodes_from_identities(identities);
        let routing_tables = test_routing_tables(identities);

        block_on(async {
            let (endpoint, router) = endpoint_router_pair(nodes, 0, 1);
            {
                let mut table = routing_tables[router].lock().await;
                table.update_peer_compact(
                    nodes[endpoint].short_addr,
                    Capabilities::LOW_ENERGY | Capabilities::APPLICATION,
                    TransportAddr::ble(nodes[endpoint].mac),
                    1,
                );
            }

            let router_caps = Capabilities::ROUTE | Capabilities::STORE;
            let candidates = collect_h2h_peer_snapshots(
                &identities[router],
                router_caps,
                &routing_tables[router],
            )
            .await;
            assert!(candidates.is_empty());
        });
    }

    #[test]
    fn initiate_h2h_fails_when_responder_behavior_is_disabled() {
        let medium = test_medium();
        let nodes = test_nodes();
        let config = test_config(2);
        config.lock().unwrap().node_behaviors[1].respond_h2h = false;

        let mut initiator = SimInitiator::new(0, medium, nodes, config);
        let result = block_on(initiator.initiate_h2h(TransportAddr::ble(nodes[1].mac), &test_payload(0x21)));

        assert!(matches!(result, Err(NetworkError::RespondDisabled)));
    }
}
