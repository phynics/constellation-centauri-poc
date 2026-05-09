//! Simulator-side retained-delivery storage for low-power endpoints.
//!
//! This module deliberately stays in `sim/` rather than `routing-core/`.
//! `routing-core` owns the H2H session semantics and role/policy predicates,
//! while the simulator owns the concrete in-memory mailbox used to exercise the
//! delayed-delivery flow.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use embassy_time::{Duration, Timer};
use routing_core::config::{STORE_FORWARD_MAX_AGE_SECS, STORE_FORWARD_MAX_PER_NODE};

use crate::sim_state::{TraceEventKind, TraceStatus, TuiState};

#[derive(Clone)]
pub struct RetainedMessage {
    pub trace_id: u64,
    pub message_id: [u8; 8],
    pub from_idx: usize,
    pub to_idx: usize,
    pub holder_idx: usize,
    /// Preferred/original router chosen when the message first entered delayed
    /// delivery. Replicas may move between holders, but the owner remains the
    /// stable rendezvous point for redundancy policy and future cleanup.
    ///
    /// In other words:
    /// - `owner_router_idx` answers "who *should* be considered the primary?"
    /// - `holder_idx` answers "who *currently stores* this copy?"
    pub owner_router_idx: usize,
    pub body: String,
    pub enqueued_at_secs: u32,
    pub announced: bool,
}

#[derive(Default)]
pub struct StoreForwardState {
    entries: Vec<RetainedMessage>,
    tombstones: Vec<u64>,
}

impl StoreForwardState {
    pub fn retain(&mut self, entry: RetainedMessage) -> bool {
        let held_for_router = self
            .entries
            .iter()
            .filter(|existing| existing.holder_idx == entry.holder_idx)
            .count();
        if held_for_router >= STORE_FORWARD_MAX_PER_NODE {
            return false;
        }
        if self.entries.iter().any(|existing| {
            existing.trace_id == entry.trace_id && existing.holder_idx == entry.holder_idx
        }) {
            return true;
        }
        self.entries.push(entry);
        true
    }

    pub fn retain_replica(&mut self, mut entry: RetainedMessage) -> bool {
        if self.entries.iter().any(|existing| {
            existing.trace_id == entry.trace_id && existing.holder_idx == entry.holder_idx
        }) {
            return true;
        }
        entry.announced = false;
        self.retain(entry)
    }

    pub fn pending_for_delivery(
        &mut self,
        holder_idx: usize,
        destination_idx: usize,
    ) -> Vec<RetainedMessage> {
        let mut pending = Vec::new();
        for entry in self.entries.iter_mut() {
            if entry.holder_idx == holder_idx && entry.to_idx == destination_idx {
                entry.announced = true;
                pending.push(entry.clone());
            }
        }
        pending
    }

    pub fn ack_delivered(&mut self, holder_idx: usize, trace_ids: &[u64]) {
        let acked: HashSet<u64> = trace_ids.iter().copied().collect();
        self.entries
            .retain(|entry| !(entry.holder_idx == holder_idx && acked.contains(&entry.trace_id)));
        for trace_id in trace_ids {
            if !self.tombstones.contains(trace_id) {
                self.tombstones.push(*trace_id);
            }
        }
    }

    pub fn apply_tombstones(&mut self, trace_ids: &[u64]) {
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

    pub fn tombstones(&self) -> &[u64] {
        &self.tombstones
    }

    pub fn replication_candidates(&self, holder_idx: usize) -> Vec<RetainedMessage> {
        self.entries
            .iter()
            .filter(|entry| entry.holder_idx == holder_idx && entry.owner_router_idx == holder_idx)
            .cloned()
            .collect()
    }

    pub fn expire(&mut self, now_secs: u32) -> Vec<RetainedMessage> {
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

    pub fn has_pending_for(&self, holder_idx: usize, destination_idx: usize) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.holder_idx == holder_idx && entry.to_idx == destination_idx)
    }

    pub fn contains_trace_at_holder(&self, trace_id: u64, holder_idx: usize) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.trace_id == trace_id && entry.holder_idx == holder_idx)
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
        let expired = state.lock().unwrap().expire(now_secs);
        if expired.is_empty() {
            continue;
        }

        let mut tui = tui_state.lock().unwrap();
        for entry in expired {
            tui.push_trace_event(
                entry.trace_id,
                entry.holder_idx,
                0,
                0,
                TraceEventKind::ExpiredFromStore,
                format!(
                    "retained delivery for low-power node {} expired at router {}",
                    entry.to_idx, entry.holder_idx
                ),
            );
            tui.set_trace_terminal_status(entry.trace_id, TraceStatus::Dropped);
        }
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
            from_idx: 0,
            to_idx: 9,
            holder_idx: 1,
            owner_router_idx: 1,
            body: "payload".into(),
            enqueued_at_secs: 0,
            announced: false,
        }));

        assert!(state.retain_replica(RetainedMessage {
            trace_id: 7,
            message_id: [0xAA; 8],
            from_idx: 0,
            to_idx: 9,
            holder_idx: 2,
            owner_router_idx: 1,
            body: "payload".into(),
            enqueued_at_secs: 1,
            announced: false,
        }));

        assert!(state.has_pending_for(1, 9));
        assert!(state.has_pending_for(2, 9));

        state.ack_delivered(2, &[7]);
        assert!(state.tombstones().contains(&7));

        state.apply_tombstones(&[7]);
        assert!(!state.has_pending_for(1, 9));
        assert!(!state.has_pending_for(2, 9));
    }
}
