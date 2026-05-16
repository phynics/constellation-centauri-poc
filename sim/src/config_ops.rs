//! Shared simulator configuration mutations.
//!
//! Purpose: centralize host-side `SimConfig` updates used by the TUI, tests,
//! and scenario helpers.
//!
//! Design decisions:
//! - Keep simulator config mutations in one place so TUI and harness flows do
//!   not drift on how scenarios and links are edited.
use crate::sim_state::{NodeBehavior, NodeType, SimConfig, MAX_NODES};

pub fn set_link_enabled(cfg: &mut SimConfig, from: usize, to: usize, enabled: bool) {
    cfg.link_enabled[from][to] = enabled;
}

pub fn set_bidirectional_link(cfg: &mut SimConfig, a: usize, b: usize, enabled: bool) {
    cfg.link_enabled[a][b] = enabled;
    cfg.link_enabled[b][a] = enabled;
}

pub fn toggle_link(cfg: &mut SimConfig, from: usize, to: usize) {
    cfg.link_enabled[from][to] = !cfg.link_enabled[from][to];
}

pub fn set_drop_prob(cfg: &mut SimConfig, from: usize, to: usize, prob: u8) {
    cfg.drop_prob[from][to] = prob.min(100);
}

pub fn set_capabilities(cfg: &mut SimConfig, node: usize, capabilities: u16) {
    cfg.capabilities[node] = capabilities;
}

pub fn toggle_capability(cfg: &mut SimConfig, node: usize, flag: u16) {
    if cfg.capabilities[node] & flag != 0 {
        cfg.capabilities[node] &= !flag;
    } else {
        cfg.capabilities[node] |= flag;
    }
}

pub fn set_node_type(cfg: &mut SimConfig, node: usize, node_type: NodeType) {
    cfg.node_types[node] = node_type;
}

pub fn update_node_behavior(cfg: &mut SimConfig, node: usize, f: impl FnOnce(&mut NodeBehavior)) {
    f(&mut cfg.node_behaviors[node]);
}

pub fn set_n_active(cfg: &mut SimConfig, n_active: usize) {
    cfg.n_active = n_active.min(MAX_NODES).max(1);
}
