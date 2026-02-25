pub const PROTOCOL_VERSION: u8 = 0x01;
pub const HEARTBEAT_INTERVAL_SECS: u64 = 60;
pub const HEARTBEAT_MAX_SUPPRESSION_SECS: u64 = 180;

// H2H (Heart2Heart) direct peer exchange
pub const H2H_CYCLE_SECS: u64 = 60;
pub const H2H_MAX_PEER_ENTRIES: usize = 8;
pub const H2H_CONNECTION_TIMEOUT_SECS: u64 = 5;
pub const H2H_PSM: u16 = 0x0081; // Dynamic range, odd
pub const H2H_MTU: u16 = 128;
pub const DEFAULT_TTL: u8 = 10;
pub const BLOOM_FILTER_BYTES: usize = 32;
pub const BLOOM_HASH_COUNT: usize = 3;
pub const SEEN_MESSAGES_CAPACITY: usize = 128;
pub const ROUTING_DECAY_FACTOR: u8 = 3;
pub const LE_DELIVERY_WINDOW_SECS: u64 = 2;
pub const STORE_FORWARD_MAX_PER_NODE: usize = 8;
pub const STORE_FORWARD_MAX_AGE_SECS: u64 = 600;
pub const MAX_PEERS: usize = 32;
pub const HEAP_SIZE: usize = 72 * 1024;
pub const HEADER_SIZE: usize = 84;
pub const BROADCAST_ADDR: [u8; 8] = [0xFF; 8];
