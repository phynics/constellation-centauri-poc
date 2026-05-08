//! Abstract network traits for H2H (Heart2Heart) peer exchange.
//!
//! These traits decouple the routing algorithm from the physical transport
//! (BLE on firmware, in-memory channels on the simulator).

use crate::crypto::identity::ShortAddr;
use crate::protocol::h2h::H2hPayload;
use heapless::Vec;

/// Maximum scan results returned per `scan()` call.
pub const MAX_SCAN_RESULTS: usize = 16;

/// A neighbor discovered via advertisement / beacon.
pub struct DiscoveryEvent {
    pub short_addr: ShortAddr,
    pub capabilities: u16,
    pub mac: [u8; 6],
}

/// Data received from an inbound H2H connection (responder side).
pub struct InboundH2h {
    pub peer_mac: [u8; 6],
    pub peer_payload: H2hPayload,
}

/// Errors that may occur during network operations.
#[derive(Debug)]
pub enum NetworkError {
    /// Generic connection failure (kept for backward compat).
    ConnectionFailed,
    /// Peer is not currently active in the simulation.
    PeerInactive,
    /// This node's H2H initiate behavior is disabled.
    InitiateDisabled,
    /// The peer's H2H respond behavior is disabled.
    RespondDisabled,
    /// The link between initiator and peer is disabled.
    LinkDisabled,
    /// The link drop probability rejected this attempt.
    DropRejected,
    ProtocolError,
    Timeout,
}

#[allow(async_fn_in_trait)]
/// Implemented by the peripheral / advertising side of a node.
///
/// The two-call protocol keeps the L2CAP channel open between `receive_h2h`
/// and `send_h2h_response`, which is necessary to build a tailored response
/// before replying (the response payload references the partner's short_addr).
pub trait H2hResponder {
    /// Wait for the next inbound H2H connection and receive the peer's payload.
    /// The underlying transport channel remains open until `send_h2h_response`
    /// is called (or this value is dropped).
    async fn receive_h2h(&mut self) -> Result<InboundH2h, NetworkError>;

    /// Send our response payload on the still-open channel from the previous
    /// `receive_h2h` call. Must be called exactly once after `receive_h2h`.
    async fn send_h2h_response(&mut self, payload: &H2hPayload) -> Result<(), NetworkError>;
}

#[allow(async_fn_in_trait)]
/// Implemented by the central / scanning side of a node.
///
/// `scan` discovers neighbors; `initiate_h2h` opens a connection and performs
/// the full initiator-side exchange.
pub trait H2hInitiator {
    /// Scan for peers for up to `duration_ms` milliseconds.
    /// Returns all discovered peers within that window.
    async fn scan(&mut self, duration_ms: u64) -> Vec<DiscoveryEvent, MAX_SCAN_RESULTS>;

    /// Connect to `peer_mac`, send `our_payload`, receive and return peer's
    /// H2H payload. The connection is closed before this returns.
    async fn initiate_h2h(
        &mut self,
        peer_mac: [u8; 6],
        our_payload: &H2hPayload,
    ) -> Result<H2hPayload, NetworkError>;
}
