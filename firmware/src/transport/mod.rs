//! Firmware transport adapters.
//!
//! Purpose: host ESP32-specific transport glue that binds shared networking
//! traits to the firmware BLE stack.
//!
//! Design decisions:
//! - Keep transport bindings here; `routing-core` should only see abstract
//!   discovery and H2H traits.

pub mod ble_network;
