//! Shared protocol-facing node capability flags.
//!
//! Purpose: define the capability bitfield and the derived predicates that the
//! protocol uses for routing, retention, and low-power behavior.
//!
//! Design decisions:
//! - Keep capability interpretation in shared core so higher-level behavior is
//!   driven by one classification source.
//! - Centralize derived predicates like low-power endpoint and store-router so
//!   call sites do not open-code behavior-critical bit tests.
//!
/// A node may advertise multiple capabilities at once. For example, a bridge
/// node is typically also a routing node, and a mobile application endpoint may
/// combine `MOBILE | APPLICATION | LOW_ENERGY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities(pub u16);

impl Capabilities {
    /// Node participates in mesh routing / forwarding decisions.
    pub const ROUTE: u16 = 0b0000_0001;
    /// Node can retain messages for deferred store-and-forward delivery.
    pub const STORE: u16 = 0b0000_0010;
    /// Node can bridge between mesh segments or transport boundaries.
    pub const BRIDGE: u16 = 0b0000_0100;
    /// Node originates or consumes application-layer payloads.
    pub const APPLICATION: u16 = 0b0000_1000;
    /// Node is energy-constrained and may be modeled as less chatty or less persistent.
    pub const LOW_ENERGY: u16 = 0b0001_0000;
    /// Node is expected to move or experience higher topology churn.
    pub const MOBILE: u16 = 0b0010_0000;

    pub const fn new(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(&self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    pub const fn is_knot(&self) -> bool {
        self.0 & Self::ROUTE != 0
    }

    pub const fn is_low_energy(&self) -> bool {
        self.0 & Self::LOW_ENERGY != 0
    }

    /// Low-power endpoint nodes are energy-constrained application leaves that
    /// do not participate in routing. Several higher-level behaviors depend on
    /// this exact classification (uplink wake scheduling, delayed delivery,
    /// router-side retention), so keep the predicate here instead of open-coded
    /// at every call site.
    pub const fn is_low_power_endpoint_bits(bits: u16) -> bool {
        bits & Self::LOW_ENERGY != 0 && bits & Self::ROUTE == 0
    }

    /// Store-capable routers are the only nodes that are currently eligible to
    /// hold delayed-delivery mail for low-power endpoints.
    pub const fn is_store_router_bits(bits: u16) -> bool {
        bits & Self::STORE != 0 && bits & Self::ROUTE != 0
    }

    pub const fn is_low_power_endpoint(&self) -> bool {
        Self::is_low_power_endpoint_bits(self.0)
    }

    pub const fn is_store_router(&self) -> bool {
        Self::is_store_router_bits(self.0)
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        self.0.to_le_bytes()
    }

    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_le_bytes(bytes))
    }
}

impl From<u16> for Capabilities {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Capabilities> for u16 {
    fn from(value: Capabilities) -> Self {
        value.0
    }
}
