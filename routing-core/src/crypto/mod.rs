//! Cryptographic primitives used by the shared mesh core.
//!
//! Purpose: group identity and payload-protection helpers that protocol code
//! depends on without pulling host-specific key management into the crate.
//!
//! Design decisions:
//! - Keep protocol-facing crypto helpers in shared core so packet, onboarding,
//!   and app-frame code share one implementation.

pub mod encryption;
pub mod identity;
