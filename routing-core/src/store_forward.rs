//! Shared delayed-delivery retention interfaces and helpers.
//!
//! Purpose: define transport-neutral store-and-forward data structures, backend
//! hooks, and helper routines used by low-power delivery flows.
//!
//! Design decisions:
//! - Keep retention semantics in shared core so firmware and simulation agree
//!   on when deferred delivery exists and how it is represented.
//! - Leave storage policy and persistence mechanics to host backends.

use alloc::vec::Vec;

use heapless::Vec as HeaplessVec;

use crate::crypto::identity::ShortAddr;
use crate::node::roles::Capabilities;
use crate::protocol::h2h::H2H_DELIVERY_BODY_MAX;
use crate::routing::table::RoutingTable;

pub type RetainedBody = HeaplessVec<u8, H2H_DELIVERY_BODY_MAX>;

#[derive(Clone)]
pub struct RetainedMessage {
    pub trace_id: u64,
    pub message_id: [u8; 8],
    pub source_addr: ShortAddr,
    pub destination_addr: ShortAddr,
    pub holder_addr: ShortAddr,
    pub owner_router_addr: ShortAddr,
    pub body: RetainedBody,
    pub enqueued_at_secs: u32,
    pub announced: bool,
}

pub trait StoreForwardBackend {
    fn retain(&mut self, entry: RetainedMessage) -> bool;
    fn retain_replica(&mut self, entry: RetainedMessage) -> bool;
    fn pending_for_delivery(
        &mut self,
        holder_addr: ShortAddr,
        destination_addr: ShortAddr,
    ) -> Vec<RetainedMessage>;
    fn ack_delivered(&mut self, holder_addr: ShortAddr, trace_ids: &[u64]);
    fn apply_tombstones(&mut self, trace_ids: &[u64]);
    fn tombstones(&self) -> Vec<u64>;
    fn replication_candidates(&self, holder_addr: ShortAddr) -> Vec<RetainedMessage>;
    fn expire(&mut self, now_secs: u32) -> Vec<RetainedMessage>;
}

pub trait StoreForwardObserver {
    fn on_pending_announced(
        &mut self,
        _trace_id: u64,
        _router_addr: ShortAddr,
        _lpn_addr: ShortAddr,
        _pending_count: usize,
    ) {
    }
    fn on_delivery_confirmed(
        &mut self,
        _trace_id: u64,
        _router_addr: ShortAddr,
        _lpn_addr: ShortAddr,
    ) {
    }
    fn on_delivered_from_store(
        &mut self,
        _trace_id: u64,
        _router_addr: ShortAddr,
        _lpn_addr: ShortAddr,
    ) {
    }
    fn on_retention_expired(
        &mut self,
        _trace_id: u64,
        _holder_addr: ShortAddr,
        _destination_addr: ShortAddr,
    ) {
    }
}

pub struct NoopStoreForwardObserver;

impl StoreForwardObserver for NoopStoreForwardObserver {}

pub fn retained_body_from_bytes(bytes: &[u8]) -> RetainedBody {
    let mut body = RetainedBody::new();
    for byte in bytes.iter().take(H2H_DELIVERY_BODY_MAX) {
        let _ = body.push(*byte);
    }
    body
}

pub fn collect_known_store_routers(
    identity_short_addr: ShortAddr,
    local_capabilities: u16,
    table: &RoutingTable,
) -> Vec<ShortAddr> {
    let mut routers = Vec::new();
    if Capabilities::is_store_router_bits(local_capabilities) {
        routers.push(identity_short_addr);
    }
    for peer in table.peers.iter() {
        if Capabilities::is_store_router_bits(peer.capabilities)
            && !routers.iter().any(|existing| *existing == peer.short_addr)
        {
            routers.push(peer.short_addr);
        }
    }
    routers
}

pub fn retain_for_low_power_destination<B: StoreForwardBackend>(
    backend: &mut B,
    trace_id: u64,
    message_id: [u8; 8],
    source_addr: ShortAddr,
    destination_addr: ShortAddr,
    holder_addr: ShortAddr,
    owner_router_addr: ShortAddr,
    body_bytes: &[u8],
    now_secs: u32,
) -> bool {
    backend.retain(RetainedMessage {
        trace_id,
        message_id,
        source_addr,
        destination_addr,
        holder_addr,
        owner_router_addr,
        body: retained_body_from_bytes(body_bytes),
        enqueued_at_secs: now_secs,
        announced: false,
    })
}

pub fn expire_retained_entries<B: StoreForwardBackend, O: StoreForwardObserver>(
    backend: &mut B,
    observer: &mut O,
    now_secs: u32,
) {
    let expired = backend.expire(now_secs);
    for entry in expired {
        observer.on_retention_expired(entry.trace_id, entry.holder_addr, entry.destination_addr);
    }
}
