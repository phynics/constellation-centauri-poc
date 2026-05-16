//! Shared node-level protocol concepts.
//!
//! Purpose: hold node metadata concepts that are part of protocol semantics
//! rather than host application models.
//!
//! Design decisions:
//! - Keep protocol-facing node traits and classifications here so host crates
//!   do not invent their own incompatible node-role vocabulary.

pub mod roles;
