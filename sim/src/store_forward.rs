//! Simulator-side retained-delivery storage for low-power endpoints.
//!
//! `routing-core` owns the protocol semantics; this module only provides the
//! simulator's concrete in-memory backend implementation.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use embassy_time::{Duration, Timer};
use routing_core::config::{STORE_FORWARD_MAX_AGE_SECS, STORE_FORWARD_MAX_PER_NODE};
use routing_core::crypto::identity::ShortAddr;
use routing_core::store_forward::{
    expire_retained_entries, RetainedMessage, StoreForwardBackend, StoreForwardObserver,
};

use crate::sim_state::{TraceEventKind, TraceStatus, TuiState};

#[derive(Default)]
pub struct StoreForwardState {
    entries: Vec<RetainedMessage>,
    tombstones: Vec<u64>,
}

#[derive(Clone)]
pub struct SharedStoreForwardBackend {
    inner: Arc<Mutex<StoreForwardState>>,
}

struct SimMaintenanceObserver {
    tui_state: Arc<Mutex<TuiState>>,
}

impl SimMaintenanceObserver {
    fn node_index_for(&self, addr: ShortAddr) -> Option<usize> {
        self.tui_state
            .lock()
            .unwrap()
            .node_short_addrs
            .iter()
            .position(|candidate| *candidate == addr)
    }
}

impl StoreForwardObserver for SimMaintenanceObserver {
    fn on_retention_expired(
        &mut self,
        trace_id: u64,
        holder_addr: ShortAddr,
        destination_addr: ShortAddr,
    ) {
        let Some(holder_idx) = self.node_index_for(holder_addr) else {
            return;
        };
        let Some(destination_idx) = self.node_index_for(destination_addr) else {
            return;
        };
        let mut tui = self.tui_state.lock().unwrap();
        tui.push_trace_event(
            trace_id,
            holder_idx,
            0,
            0,
            TraceEventKind::ExpiredFromStore,
            format!(
                "retained delivery for low-power node {} expired at router {}",
                destination_idx, holder_idx
            ),
        );
        tui.set_trace_terminal_status(trace_id, TraceStatus::Dropped);
    }
}

impl SharedStoreForwardBackend {
    pub fn new(inner: Arc<Mutex<StoreForwardState>>) -> Self {
        Self { inner }
    }
}

impl StoreForwardBackend for StoreForwardState {
    fn retain(&mut self, entry: RetainedMessage) -> bool {
        let held_for_router = self
            .entries
            .iter()
            .filter(|existing| existing.holder_addr == entry.holder_addr)
            .count();
        if held_for_router >= STORE_FORWARD_MAX_PER_NODE {
            return false;
        }
        if self.entries.iter().any(|existing| {
            existing.trace_id == entry.trace_id && existing.holder_addr == entry.holder_addr
        }) {
            return true;
        }
        self.entries.push(entry);
        true
    }

    fn retain_replica(&mut self, mut entry: RetainedMessage) -> bool {
        if self.entries.iter().any(|existing| {
            existing.trace_id == entry.trace_id && existing.holder_addr == entry.holder_addr
        }) {
            return true;
        }
        entry.announced = false;
        self.retain(entry)
    }

    fn pending_for_delivery(
        &mut self,
        holder_addr: ShortAddr,
        destination_addr: ShortAddr,
    ) -> Vec<RetainedMessage> {
        let mut pending = Vec::new();
        for entry in self.entries.iter_mut() {
            if entry.holder_addr == holder_addr && entry.destination_addr == destination_addr {
                entry.announced = true;
                pending.push(entry.clone());
            }
        }
        pending
    }

    fn ack_delivered(&mut self, holder_addr: ShortAddr, trace_ids: &[u64]) {
        let acked: HashSet<u64> = trace_ids.iter().copied().collect();
        self.entries
            .retain(|entry| !(entry.holder_addr == holder_addr && acked.contains(&entry.trace_id)));
        for trace_id in trace_ids {
            if !self.tombstones.contains(trace_id) {
                self.tombstones.push(*trace_id);
            }
        }
    }

    fn apply_tombstones(&mut self, trace_ids: &[u64]) {
        if trace_ids.is_empty() {
            return;
        }
        // Tombstones intentionally act across all holders, not just the router
        // that generated them. Once any router has completed delayed delivery,
        // other retained copies become stale redundancy and should be removed.
        let cleared: HashSet<u64> = trace_ids.iter().copied().collect();
        self.entries
            .retain(|entry| !cleared.contains(&entry.trace_id));
        for trace_id in trace_ids {
            if !self.tombstones.contains(trace_id) {
                self.tombstones.push(*trace_id);
            }
        }
    }

    fn tombstones(&self) -> Vec<u64> {
        self.tombstones.clone()
    }

    fn replication_candidates(&self, holder_addr: ShortAddr) -> Vec<RetainedMessage> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.holder_addr == holder_addr && entry.owner_router_addr == holder_addr
            })
            .cloned()
            .collect()
    }

    fn expire(&mut self, now_secs: u32) -> Vec<RetainedMessage> {
        let mut expired = Vec::new();
        self.entries.retain(|entry| {
            let age = now_secs.saturating_sub(entry.enqueued_at_secs) as u64;
            if age > STORE_FORWARD_MAX_AGE_SECS {
                expired.push(entry.clone());
                false
            } else {
                true
            }
        });
        expired
    }
}

impl StoreForwardState {
    pub fn has_pending_for(&self, holder_addr: ShortAddr, destination_addr: ShortAddr) -> bool {
        self.entries.iter().any(|entry| {
            entry.holder_addr == holder_addr && entry.destination_addr == destination_addr
        })
    }

    pub fn contains_trace_at_holder(&self, trace_id: u64, holder_addr: ShortAddr) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.trace_id == trace_id && entry.holder_addr == holder_addr)
    }
}

impl StoreForwardBackend for SharedStoreForwardBackend {
    fn retain(&mut self, entry: RetainedMessage) -> bool {
        self.inner.lock().unwrap().retain(entry)
    }

    fn retain_replica(&mut self, entry: RetainedMessage) -> bool {
        self.inner.lock().unwrap().retain_replica(entry)
    }

    fn pending_for_delivery(
        &mut self,
        holder_addr: ShortAddr,
        destination_addr: ShortAddr,
    ) -> Vec<RetainedMessage> {
        self.inner
            .lock()
            .unwrap()
            .pending_for_delivery(holder_addr, destination_addr)
    }

    fn ack_delivered(&mut self, holder_addr: ShortAddr, trace_ids: &[u64]) {
        self.inner
            .lock()
            .unwrap()
            .ack_delivered(holder_addr, trace_ids);
    }

    fn apply_tombstones(&mut self, trace_ids: &[u64]) {
        self.inner.lock().unwrap().apply_tombstones(trace_ids);
    }

    fn tombstones(&self) -> Vec<u64> {
        self.inner.lock().unwrap().tombstones()
    }

    fn replication_candidates(&self, holder_addr: ShortAddr) -> Vec<RetainedMessage> {
        self.inner
            .lock()
            .unwrap()
            .replication_candidates(holder_addr)
    }

    fn expire(&mut self, now_secs: u32) -> Vec<RetainedMessage> {
        self.inner.lock().unwrap().expire(now_secs)
    }
}

/// Periodically expires retained messages that were never collected by a waking
/// low-power endpoint. The trace stays `Pending` while retained and transitions
/// to `Dropped` only once the retention window has actually elapsed.
pub async fn run_store_forward_maintenance(
    state: Arc<Mutex<StoreForwardState>>,
    tui_state: Arc<Mutex<TuiState>>,
) -> ! {
    loop {
        Timer::after(Duration::from_secs(1)).await;

        let now_secs = tui_state.lock().unwrap().elapsed_secs;
        let mut backend = SharedStoreForwardBackend::new(Arc::clone(&state));
        let mut observer = SimMaintenanceObserver {
            tui_state: Arc::clone(&tui_state),
        };
        expire_retained_entries(&mut backend, &mut observer, now_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replica_and_tombstone_cleanup_work_across_holders() {
        let mut state = StoreForwardState::default();

        assert!(state.retain(RetainedMessage {
            trace_id: 7,
            message_id: [0xAA; 8],
            source_addr: [0x10; 8],
            destination_addr: [0x90; 8],
            holder_addr: [0x11; 8],
            owner_router_addr: [0x11; 8],
            body: routing_core::store_forward::retained_body_from_bytes(b"payload"),
            enqueued_at_secs: 0,
            announced: false,
        }));

        assert!(state.retain_replica(RetainedMessage {
            trace_id: 7,
            message_id: [0xAA; 8],
            source_addr: [0x10; 8],
            destination_addr: [0x90; 8],
            holder_addr: [0x22; 8],
            owner_router_addr: [0x11; 8],
            body: routing_core::store_forward::retained_body_from_bytes(b"payload"),
            enqueued_at_secs: 1,
            announced: false,
        }));

        assert!(state.has_pending_for([0x11; 8], [0x90; 8]));
        assert!(state.has_pending_for([0x22; 8], [0x90; 8]));

        state.ack_delivered([0x22; 8], &[7]);
        assert!(state.tombstones().contains(&7));

        state.apply_tombstones(&[7]);
        assert!(!state.has_pending_for([0x11; 8], [0x90; 8]));
        assert!(!state.has_pending_for([0x22; 8], [0x90; 8]));
    }
}
