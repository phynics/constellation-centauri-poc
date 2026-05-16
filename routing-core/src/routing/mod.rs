//! Shared routing-table data structures.
//!
//! Purpose: group the routing table and compact reachability-summary helpers
//! used by the core forwarding logic.
//!
//! Design decisions:
//! - Keep reachability summaries adjacent to routing-table state so forwarding
//!   behavior is implemented from one shared model.

pub mod bloom;
pub mod table;
