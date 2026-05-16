//! Shared no-std protocol crate for Constellation Mesh.
//!
//! This crate owns transport-agnostic routing, packet formats, H2H behavior,
//! crypto helpers, and node-role policy used by both firmware and simulator.

#![no_std]

// For alloc-dependent crypto (chacha20poly1305)
extern crate alloc;

pub mod behavior;
pub mod config;
pub mod crypto;
pub mod facade;
pub mod message;
pub mod network;
pub mod node;
pub mod onboarding;
pub mod protocol;
pub mod routing;
pub mod store_forward;
pub mod transport;
