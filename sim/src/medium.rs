//! Simulated radio medium.
//!
//! Each node has:
//! - An H2H **inbox** (`h2h_req[node_idx]`): receives H2H requests from initiators.
//! - An H2H **response** channel (`h2h_resp[node_idx]`): the responder puts its
//!   payload here for the initiator to collect.
//! - A **data inbox** (`msg_inbox[node_idx]`): receives application data messages.
//!
//! The responder reads from its own inbox, processes the request, and puts the
//! response into the *initiator's* response channel (`h2h_resp[sender_idx]`).

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;

use routing_core::network::NetworkError;
use routing_core::protocol::h2h::H2hPayload;

use crate::sim_state::MAX_NODES;

/// Maximum H2H payload size in bytes.  Must be >= H2hPayload::max_size() = 321.
const PAYLOAD_BUF: usize = 512;

/// An H2H request from one node to another.
pub struct SimH2hRequest {
    /// Index of the node that initiated this request.
    pub sender_idx: usize,
    /// Serialised H2H payload from the initiator.
    pub payload_bytes: [u8; PAYLOAD_BUF],
    pub payload_len: usize,
}

/// Response (or error) to an H2H request, placed in the initiator's response slot.
pub struct SimH2hResponse {
    pub result: Result<([u8; PAYLOAD_BUF], usize), NetworkError>,
}

/// Application-level data message delivered between nodes.
pub struct SimDataMessage {
    pub trace_id: u64,
}

/// Per-node mailboxes.  All channels use `CriticalSectionRawMutex` so they work
/// safely across embassy tasks running on the same std thread.
pub struct SimMedium {
    /// Inbox per node: initiators push here for the responder to handle.
    pub h2h_req: [Channel<CriticalSectionRawMutex, SimH2hRequest, 1>; MAX_NODES],
    /// Response slot per node: responder pushes here; initiator reads its own slot.
    pub h2h_resp: [Channel<CriticalSectionRawMutex, SimH2hResponse, 1>; MAX_NODES],
    /// Application data inbox per node.
    pub msg_inbox: [Channel<CriticalSectionRawMutex, SimDataMessage, 4>; MAX_NODES],
}

impl SimMedium {
    pub const fn new() -> Self {
        Self {
            h2h_req: [
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
            ],
            h2h_resp: [
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
            ],
            msg_inbox: [
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
                Channel::new(),
            ],
        }
    }
}

/// Serialise an `H2hPayload` into a fixed buffer.
pub fn serialize_payload(payload: &H2hPayload) -> Option<([u8; PAYLOAD_BUF], usize)> {
    let mut buf = [0u8; PAYLOAD_BUF];
    match payload.serialize(&mut buf) {
        Ok(n) => Some((buf, n)),
        Err(_) => None,
    }
}

/// Deserialise an `H2hPayload` from a fixed buffer slice.
pub fn deserialize_payload(bytes: &[u8; PAYLOAD_BUF], len: usize) -> Option<H2hPayload> {
    H2hPayload::deserialize(&bytes[..len]).ok()
}
