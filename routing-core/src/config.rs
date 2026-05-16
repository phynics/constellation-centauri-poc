//! Shared routing-core constants.
//!
//! Purpose: centralize protocol and behavior constants that must stay aligned
//! across firmware, host tools, and tests.
//!
//! Design decisions:
//! - Keep wire-level and behavior-tuning constants in shared core so hosts do
//!   not drift on protocol layout or scheduling assumptions.
//! - Prefer explicit fixed capacities and sizes over dynamic configuration in
//!   the core protocol path.

pub const PROTOCOL_VERSION: u8 = 0x01;
pub const HEARTBEAT_INTERVAL_SECS: u64 = 60;
pub const HEARTBEAT_MAX_SUPPRESSION_SECS: u64 = 180;

// H2H (Heart2Heart) direct peer exchange
pub const H2H_CYCLE_SECS: u64 = 60;
pub const H2H_MAX_PEER_ENTRIES: usize = 8;
pub const H2H_CONNECTION_TIMEOUT_SECS: u64 = 5;
pub const H2H_PSM: u16 = 0x0081; // Dynamic range, odd
pub const H2H_MTU: u16 = 512;
pub const DEFAULT_TTL: u8 = 10;
pub const BLOOM_FILTER_BYTES: usize = 32;
pub const BLOOM_HASH_COUNT: usize = 3;
pub const SEEN_MESSAGES_CAPACITY: usize = 128;
pub const ROUTING_DECAY_FACTOR: u8 = 3;
pub const LE_DELIVERY_WINDOW_SECS: u64 = 2;
pub const STORE_FORWARD_MAX_PER_NODE: usize = 8;
pub const STORE_FORWARD_MAX_AGE_SECS: u64 = 600;
pub const STORE_FORWARD_BACKUP_ROUTERS: usize = 2;
pub const MAX_PEERS: usize = 32;
/// Embassy on ESP32 defaults to 1 MHz tick rate.
pub const TICK_HZ: u64 = 1_000_000;
pub const HEADER_SIZE: usize = 92;
pub const BROADCAST_ADDR: [u8; 8] = [0xFF; 8];
