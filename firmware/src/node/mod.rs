//! Firmware-only node services.
//!
//! Purpose: group flash-backed identity and provisioning helpers that depend on
//! ESP32 storage details rather than shared protocol semantics.
//!
//! Design decisions:
//! - Keep persistence and partition handling here; `routing-core` owns the
//!   transport-neutral identity and onboarding data structures.

pub mod partitioned_flash;
pub mod storage;
