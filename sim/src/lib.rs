//! Desktop simulator crate for exercising routing-core against an in-memory medium.

pub mod behavior;
pub mod command_task;
pub mod config_ops;
pub mod export;
pub mod harness;
pub mod medium;
pub mod network;
pub mod runtime;
pub mod scenario;
pub mod sim_state;
pub mod snapshot_task;
pub mod store_forward;
pub mod tui;
pub mod tui_logger;

mod message_task;
