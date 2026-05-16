//! Shared wire-level protocol modules.
//!
//! Purpose: group packet, H2H, routed app, heartbeat, and dedup logic under
//! one protocol-facing namespace.
//!
//! Design decisions:
//! - Keep wire-format modules together in shared core so protocol evolution is
//!   implemented once and consumed consistently by all hosts.

pub mod app;
pub mod dedup;
pub mod h2h;
pub mod heartbeat;
pub mod packet;
