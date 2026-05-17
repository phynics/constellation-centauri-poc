//! Shared transport-neutral routed-message decisions.
//!
//! Purpose: decide whether a routed message is delivered, forwarded, retained,
//! or dropped without depending on any host runtime or transport stack.
//!
//! Design decisions:
//! - Keep forwarding and retention decisions in shared core so simulator and
//!   firmware cannot drift on delivery behavior.
//! - Own the canonical routed-envelope and routed-decision types here; higher
//!   layers may compose or re-export them but should not redefine them.
//! - Return plans and decisions instead of performing transport actions here.

use heapless::Vec;

use crate::config::BROADCAST_ADDR;
use crate::crypto::identity::ShortAddr;
use crate::node::roles::Capabilities;
use crate::routing::table::{RoutingTable, TRUST_EXPIRED};
use crate::transport::TransportAddr;

pub const MAX_FORWARD_CANDIDATES: usize = 8;

#[derive(Clone, Copy)]
pub struct RoutedEnvelope {
    pub destination: ShortAddr,
    pub is_broadcast: bool,
    pub message_id: [u8; 8],
    pub ttl: u8,
    pub hop_count: u8,
}

pub struct ForwardPlan {
    pub observe_broadcast: bool,
    pub candidates: Vec<(ShortAddr, TransportAddr), MAX_FORWARD_CANDIDATES>,
    pub should_retain_for_lpn: bool,
}

pub enum RoutedDecision {
    TtlExpired,
    Duplicate,
    DeliveredLocal,
    Forward(ForwardPlan),
    NoRoute {
        observe_broadcast: bool,
        should_retain_for_lpn: bool,
    },
}

pub fn route_message(
    table: &mut RoutingTable,
    local_capabilities: Capabilities,
    destination_is_low_power: bool,
    local_addr: ShortAddr,
    msg: &RoutedEnvelope,
) -> RoutedDecision {
    if msg.ttl == 0 {
        return RoutedDecision::TtlExpired;
    }

    if table.seen.check_and_insert(&msg.message_id) {
        return RoutedDecision::Duplicate;
    }

    if !msg.is_broadcast && local_addr == msg.destination {
        return RoutedDecision::DeliveredLocal;
    }

    let observe_broadcast = msg.is_broadcast;
    let mut candidates = Vec::new();

    if msg.is_broadcast {
        for peer in table.peers.iter() {
            if peer.trust <= TRUST_EXPIRED || peer.transport_addr.is_empty() {
                continue;
            }
            if candidates
                .push((peer.short_addr, peer.transport_addr))
                .is_err()
            {
                break;
            }
        }
    } else {
        candidates = table.forwarding_candidates(&msg.destination);
    }

    let should_retain_for_lpn =
        !msg.is_broadcast && destination_is_low_power && local_capabilities.is_store_router();

    if candidates.is_empty() {
        RoutedDecision::NoRoute {
            observe_broadcast,
            should_retain_for_lpn,
        }
    } else {
        RoutedDecision::Forward(ForwardPlan {
            observe_broadcast,
            candidates,
            should_retain_for_lpn,
        })
    }
}

pub fn broadcast_destination() -> ShortAddr {
    BROADCAST_ADDR
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::table::{RoutingTable, TRUST_DIRECT};

    fn short(seed: u8) -> ShortAddr {
        [seed, 0, 0, 0, 0, 0, 0, 0]
    }

    fn transport(seed: u8) -> TransportAddr {
        TransportAddr::ble([seed; 6])
    }

    #[test]
    fn delivers_local_directed_message() {
        let self_addr = short(1);
        let mut table = RoutingTable::new(self_addr);
        let msg = RoutedEnvelope {
            destination: self_addr,
            is_broadcast: false,
            message_id: [1; 8],
            ttl: 3,
            hop_count: 0,
        };

        assert!(matches!(
            route_message(&mut table, Capabilities::new(0), false, self_addr, &msg),
            RoutedDecision::DeliveredLocal
        ));
    }

    #[test]
    fn duplicates_are_rejected() {
        let self_addr = short(1);
        let mut table = RoutingTable::new(self_addr);
        let msg = RoutedEnvelope {
            destination: short(2),
            is_broadcast: false,
            message_id: [9; 8],
            ttl: 3,
            hop_count: 0,
        };

        let _ = route_message(&mut table, Capabilities::new(0), false, self_addr, &msg);
        assert!(matches!(
            route_message(&mut table, Capabilities::new(0), false, self_addr, &msg),
            RoutedDecision::Duplicate
        ));
    }

    #[test]
    fn forwards_to_direct_candidate() {
        let self_addr = short(1);
        let dst = short(2);
        let mut table = RoutingTable::new(self_addr);
        let _ = table.peers.push(crate::routing::table::PeerEntry {
            pubkey: [0; 32],
            short_addr: dst,
            capabilities: Capabilities::new(0),
            bloom: crate::routing::bloom::BloomFilter::new(),
            transport_addr: transport(7),
            last_seen_ticks: 1,
            hop_count: 0,
            trust: TRUST_DIRECT,
            learned_from: [0; 8],
        });
        let msg = RoutedEnvelope {
            destination: dst,
            is_broadcast: false,
            message_id: [1; 8],
            ttl: 3,
            hop_count: 0,
        };

        match route_message(&mut table, Capabilities::new(0), false, self_addr, &msg) {
            RoutedDecision::Forward(plan) => {
                assert_eq!(plan.candidates.len(), 1);
                assert_eq!(plan.candidates[0].0, dst);
            }
            _ => panic!("expected forward decision"),
        }
    }

    #[test]
    fn returns_retain_hint_for_store_router_lpn_miss() {
        let self_addr = short(1);
        let mut table = RoutingTable::new(self_addr);
        let msg = RoutedEnvelope {
            destination: short(3),
            is_broadcast: false,
            message_id: [1; 8],
            ttl: 3,
            hop_count: 0,
        };

        match route_message(
            &mut table,
            Capabilities::new(Capabilities::ROUTE | Capabilities::STORE),
            true,
            self_addr,
            &msg,
        ) {
            RoutedDecision::NoRoute {
                should_retain_for_lpn,
                ..
            } => assert!(should_retain_for_lpn),
            _ => panic!("expected no-route retain hint"),
        }
    }
}
