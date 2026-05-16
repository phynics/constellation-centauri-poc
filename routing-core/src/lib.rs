//! Shared no-std routing and protocol core for Constellation Mesh.
//!
//! Purpose: keep protocol, routing, crypto, onboarding, and transport-neutral
//! behavior in one crate that both firmware and host harnesses can reuse.
//!
//! Design decisions:
//! - Keep transport-agnostic mesh behavior here; host crates provide runtime,
//!   BLE, storage, and UI glue.
//! - Prefer fixed-capacity and `no_std`-friendly building blocks so the same
//!   code can run on embedded targets and in host-side tests.

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
