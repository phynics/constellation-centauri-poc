//! Companion-local node services.
//!
//! Purpose: group host-side persistence helpers for the companion's local node
//! identity and related records.
//!
//! Design decisions:
//! - Keep macOS/local filesystem storage here while shared identity types remain
//!   in `routing-core`.
pub mod storage;
