//! `SimResponder` and `SimInitiator` — in-process implementations of the
//! `H2hResponder` / `H2hInitiator` traits using `SimMedium` channels.
//!
//! Topology and packet-drop behaviour are driven by `SimConfig` at runtime,
//! so the TUI can toggle links and adjust drop probabilities on the fly.

use std::sync::{Arc, Mutex};

use heapless::Vec;
use embassy_time::{Duration, Timer};
use rand::Rng as _;

use routing_core::network::{
    DiscoveryEvent, H2hInitiator, H2hResponder, InboundH2h, MAX_SCAN_RESULTS, NetworkError,
};
use routing_core::protocol::h2h::H2hPayload;

use crate::medium::{
    deserialize_payload, serialize_payload, SimH2hRequest, SimH2hResponse, SimMedium,
};
use crate::sim_state::{SimConfig, MAX_NODES};

// ── Peer info shared across all sim nodes ─────────────────────────────────────

/// Static info about every simulated node, shared with all `SimInitiator`s.
pub struct SimNodeInfo {
    pub short_addr: [u8; 8],
    pub capabilities: u16,
    /// MAC used on the simulated medium.  Convention: `mac[0] = node_index`.
    pub mac: [u8; 6],
}

// ── SimResponder ──────────────────────────────────────────────────────────────

pub struct SimResponder {
    node_idx: usize,
    medium: &'static SimMedium,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
    pending_sender: Option<usize>,
}

impl SimResponder {
    pub fn new(
        node_idx: usize,
        medium: &'static SimMedium,
        all_nodes: &'static [SimNodeInfo; MAX_NODES],
    ) -> Self {
        Self { node_idx, medium, all_nodes, pending_sender: None }
    }
}

impl H2hResponder for SimResponder {
    async fn receive_h2h(&mut self) -> Result<InboundH2h, NetworkError> {
        let req = self.medium.h2h_req[self.node_idx].receive().await;

        let peer_payload = deserialize_payload(&req.payload_bytes, req.payload_len)
            .ok_or(NetworkError::ProtocolError)?;

        let peer_mac = self.all_nodes[req.sender_idx].mac;
        self.pending_sender = Some(req.sender_idx);

        Ok(InboundH2h { peer_mac, peer_payload })
    }

    async fn send_h2h_response(&mut self, payload: &H2hPayload) -> Result<(), NetworkError> {
        let sender_idx = self.pending_sender.take().ok_or(NetworkError::ProtocolError)?;

        let (bytes, len) = serialize_payload(payload).ok_or(NetworkError::ProtocolError)?;

        self.medium.h2h_resp[sender_idx]
            .send(SimH2hResponse { result: Ok((bytes, len)) })
            .await;

        Ok(())
    }
}

// ── SimInitiator ──────────────────────────────────────────────────────────────

pub struct SimInitiator {
    node_idx: usize,
    medium: &'static SimMedium,
    all_nodes: &'static [SimNodeInfo; MAX_NODES],
    sim_config: Arc<Mutex<SimConfig>>,
}

impl SimInitiator {
    pub fn new(
        node_idx: usize,
        medium: &'static SimMedium,
        all_nodes: &'static [SimNodeInfo; MAX_NODES],
        sim_config: Arc<Mutex<SimConfig>>,
    ) -> Self {
        Self { node_idx, medium, all_nodes, sim_config }
    }
}

impl H2hInitiator for SimInitiator {
    async fn scan(&mut self, duration_ms: u64) -> Vec<DiscoveryEvent, MAX_SCAN_RESULTS> {
        // Simulate scan latency.
        Timer::after(Duration::from_millis(duration_ms)).await;

        let config = self.sim_config.lock().unwrap();

        // Inactive nodes don't scan.
        if self.node_idx >= config.n_active {
            return Vec::new();
        }

        let mut results = Vec::new();
        for (i, node) in self.all_nodes.iter().enumerate() {
            if i == self.node_idx || i >= config.n_active {
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
            let _ = results.push(DiscoveryEvent {
                short_addr: node.short_addr,
                capabilities: node.capabilities,
                mac: node.mac,
            });
        }
        results
    }

    async fn initiate_h2h(
        &mut self,
        peer_mac: [u8; 6],
        our_payload: &H2hPayload,
    ) -> Result<H2hPayload, NetworkError> {
        // Convention: mac[0] = node_index in the simulator.
        let peer_idx = peer_mac[0] as usize;
        if peer_idx >= MAX_NODES {
            return Err(NetworkError::ConnectionFailed);
        }

        // Check config: inactive peer or simulated packet drop.
        {
            let config = self.sim_config.lock().unwrap();
            if peer_idx >= config.n_active {
                return Err(NetworkError::ConnectionFailed);
            }
            if !config.link_enabled[self.node_idx][peer_idx] {
                return Err(NetworkError::ConnectionFailed);
            }
            let drop = config.drop_prob[self.node_idx][peer_idx];
            if drop > 0 && rand::thread_rng().gen_range(0u8..100) < drop {
                return Err(NetworkError::ConnectionFailed);
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
        deserialize_payload(&resp_bytes, resp_len).ok_or(NetworkError::ProtocolError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::mutex::Mutex as AsyncMutex;
    use pollster::block_on;
    use routing_core::behavior::{apply_discovery_events, run_initiator_h2h_once};
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

        SimNodeInfo {
            short_addr,
            capabilities: 0x1000 + idx as u16,
            mac,
        }
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
            SimNodeInfo {
                short_addr,
                capabilities: 0x1000 + i as u16,
                mac,
            }
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
        assert!(results.iter().all(|event| event.mac != nodes[0].mac));
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
        let result = block_on(initiator.initiate_h2h(nodes[1].mac, &test_payload(0x21)));

        assert!(matches!(result, Err(NetworkError::ConnectionFailed)));
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
            move || {
                let mut responder = SimResponder::new(1, medium, nodes);
                block_on(async {
                    let inbound = responder.receive_h2h().await.unwrap();
                    assert_eq!(inbound.peer_mac, nodes[0].mac);
                    assert_eq!(inbound.peer_payload.full_pubkey, request_payload.full_pubkey);
                    assert_eq!(inbound.peer_payload.capabilities, request_payload.capabilities);
                    assert_eq!(inbound.peer_payload.uptime_secs, request_payload.uptime_secs);
                    responder.send_h2h_response(&response_payload).await.unwrap();
                });
            }
        });

        let mut initiator = SimInitiator::new(0, medium, nodes, config);
        let received = block_on(initiator.initiate_h2h(nodes[1].mac, &request_payload)).unwrap();

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
                    capabilities: nodes[node_c].capabilities,
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
            let mut responder = SimResponder::new(node_b, medium, nodes);

            let scan_results = initiator.scan(0).await;
            apply_discovery_events(&routing_tables[node_a], &scan_results).await;

            let response = routing_core::behavior::build_h2h_payload(
                &identities[node_b],
                nodes[node_b].capabilities,
                &uptimes[node_b],
                &routing_tables[node_b],
                identities[node_a].short_addr(),
            )
            .await;

            let responder_thread = std::thread::spawn(move || {
                block_on(async {
                    let inbound = responder.receive_h2h().await.unwrap();
                    assert_eq!(inbound.peer_mac, nodes[node_a].mac);
                    responder.send_h2h_response(&response).await.unwrap();
                });
            });

            run_initiator_h2h_once(
                &mut initiator,
                &identities[node_a],
                nodes[node_a].capabilities,
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
                assert_eq!(b_entry.transport_addr.addr, nodes[node_b].mac);
            }

            {
                let mut cfg = config.lock().unwrap();
                cfg.link_enabled[node_a][node_b] = false;
            }

            let disabled_scan = initiator.scan(0).await;
            assert!(disabled_scan.is_empty());

            let disabled_h2h = initiator.initiate_h2h(nodes[node_b].mac, &test_payload(0x55)).await;
            assert!(matches!(disabled_h2h, Err(NetworkError::ConnectionFailed)));

            {
                let mut cfg = config.lock().unwrap();
                cfg.link_enabled[node_a][node_b] = true;
            }

            let reenabled_scan = initiator.scan(0).await;
            assert_eq!(reenabled_scan.len(), 1);
            apply_discovery_events(&routing_tables[node_a], &reenabled_scan).await;

            let response = routing_core::behavior::build_h2h_payload(
                &identities[node_b],
                nodes[node_b].capabilities,
                &uptimes[node_b],
                &routing_tables[node_b],
                identities[node_a].short_addr(),
            )
            .await;

            let mut responder = SimResponder::new(node_b, medium, nodes);
            let responder_thread = std::thread::spawn(move || {
                block_on(async {
                    let inbound = responder.receive_h2h().await.unwrap();
                    assert_eq!(inbound.peer_mac, nodes[node_a].mac);
                    responder.send_h2h_response(&response).await.unwrap();
                });
            });

            run_initiator_h2h_once(
                &mut initiator,
                &identities[node_a],
                nodes[node_a].capabilities,
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
}
