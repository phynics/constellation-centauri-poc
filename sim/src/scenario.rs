//! Built-in simulator scenarios and helpers for applying them.

use routing_core::node::roles::Capabilities;

use crate::sim_state::{NodeBehavior, NodeType, SimConfig, DEFAULT_NODES, MAX_NODES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScenarioId {
    FullMeshBaseline,
    PartitionedBridge,
    LossyEdge,
    FieldDeployment,
}

#[derive(Clone, Copy, Debug)]
pub struct ScenarioPreset {
    pub id: ScenarioId,
    pub name: &'static str,
    pub description: &'static str,
    pub expected_outcome: &'static str,
}

const PRESETS: [ScenarioPreset; 4] = [
    ScenarioPreset {
        id: ScenarioId::FullMeshBaseline,
        name: "Full mesh baseline",
        description: "12 active nodes in a healthy mesh with mostly low-energy endpoints.",
        expected_outcome:
            "Routing nodes should quickly learn all endpoints directly; one mobile endpoint should churn a little but still converge.",
    },
    ScenarioPreset {
        id: ScenarioId::PartitionedBridge,
        name: "Partitioned bridge",
        description: "18 active nodes split into two clusters with a single bridge corridor.",
        expected_outcome:
            "Each cluster should converge internally, while cross-cluster visibility should depend on the bridge path.",
    },
    ScenarioPreset {
        id: ScenarioId::LossyEdge,
        name: "Lossy edge",
        description: "14 active nodes with two mobile edge nodes and one weak corridor.",
        expected_outcome:
            "Core routing nodes should stabilize first while the lossy mobile edge flaps between seen and unseen states.",
    },
    ScenarioPreset {
        id: ScenarioId::FieldDeployment,
        name: "Field deployment",
        description: "20 active nodes with many low-energy nodes, several routers, and two app nodes.",
        expected_outcome:
            "The mesh should stay connected while application nodes generate traffic through a sparse routing backbone.",
    },
];

pub fn presets() -> &'static [ScenarioPreset] {
    &PRESETS
}

pub fn preset(id: ScenarioId) -> &'static ScenarioPreset {
    PRESETS
        .iter()
        .find(|preset| preset.id == id)
        .unwrap_or(&PRESETS[0])
}

pub fn default_scenario() -> ScenarioId {
    ScenarioId::FullMeshBaseline
}

pub fn build_config(id: ScenarioId) -> SimConfig {
    match id {
        ScenarioId::FullMeshBaseline => full_mesh_baseline(),
        ScenarioId::PartitionedBridge => partitioned_bridge(),
        ScenarioId::LossyEdge => lossy_edge(),
        ScenarioId::FieldDeployment => field_deployment(),
    }
}

fn full_mesh_baseline() -> SimConfig {
    let mut cfg = blank_config(DEFAULT_NODES);

    assign_low_energy(&mut cfg, &[4, 5, 6, 7, 8, 9, 10, 11]);
    assign_routing(&mut cfg, &[0, 1, 2]);
    assign_application(&mut cfg, &[3]);
    assign_mobile(&mut cfg, &[11]);

    cfg
}

fn partitioned_bridge() -> SimConfig {
    let mut cfg = blank_config(18);
    disable_all_links(&mut cfg);

    assign_low_energy(&mut cfg, &[4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17]);
    assign_routing(&mut cfg, &[0, 1, 2, 3]);
    assign_application(&mut cfg, &[14]);
    assign_bridge(&mut cfg, 15);
    assign_mobile(&mut cfg, &[17]);

    // Cluster A
    for &(a, b) in &[
        (0, 4),
        (0, 5),
        (1, 6),
        (1, 7),
        (2, 8),
        (2, 9),
        (0, 1),
        (1, 2),
    ] {
        enable_bidirectional_link(&mut cfg, a, b);
    }
    // Cluster B
    for &(a, b) in &[
        (3, 10),
        (3, 11),
        (3, 12),
        (3, 13),
        (3, 14),
        (3, 16),
        (3, 17),
    ] {
        enable_bidirectional_link(&mut cfg, a, b);
    }
    // Bridge corridor
    enable_bidirectional_link(&mut cfg, 2, 15);
    enable_bidirectional_link(&mut cfg, 15, 3);
    cfg.drop_prob[15][3] = 10;
    cfg.drop_prob[3][15] = 10;

    cfg
}

fn lossy_edge() -> SimConfig {
    let mut cfg = blank_config(14);

    assign_low_energy(&mut cfg, &[4, 5, 6, 7, 8, 9, 10, 12, 13]);
    assign_routing(&mut cfg, &[0, 1, 2]);
    assign_application(&mut cfg, &[3]);
    assign_mobile(&mut cfg, &[12, 13]);

    cfg.drop_prob[12][2] = 55;
    cfg.drop_prob[2][12] = 35;
    cfg.drop_prob[13][2] = 65;
    cfg.drop_prob[2][13] = 40;
    cfg.drop_prob[12][13] = 25;
    cfg.drop_prob[13][12] = 25;

    cfg
}

fn field_deployment() -> SimConfig {
    let mut cfg = blank_config(20);
    cfg.sensor_auto = true;
    cfg.sensor_interval_secs = 4;

    assign_low_energy(
        &mut cfg,
        &[5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
    );
    assign_routing(&mut cfg, &[0, 1, 2, 3, 4]);
    assign_application(&mut cfg, &[17, 18]);
    assign_mobile(&mut cfg, &[19]);

    // Make the largest preset slightly sparser than full mesh so the topology view is informative.
    for i in 5..20 {
        for j in 5..20 {
            if i != j {
                cfg.link_enabled[i][j] = false;
            }
        }
    }
    for endpoint in 5..20 {
        let router = endpoint % 5;
        enable_bidirectional_link(&mut cfg, endpoint, router);
        if endpoint + 1 < 20 && endpoint % 2 == 1 {
            enable_bidirectional_link(&mut cfg, endpoint, endpoint + 1);
        }
    }

    cfg
}

fn blank_config(n_active: usize) -> SimConfig {
    let mut cfg = SimConfig::default();
    cfg.n_active = n_active;
    cfg.capabilities = [0; MAX_NODES];
    cfg.node_types = core::array::from_fn(|_| NodeType::Sensor);
    cfg.node_behaviors = core::array::from_fn(|_| NodeBehavior::default());
    cfg
}

fn disable_all_links(cfg: &mut SimConfig) {
    for from in 0..MAX_NODES {
        for to in 0..MAX_NODES {
            cfg.link_enabled[from][to] = false;
        }
    }
}

fn assign_low_energy(cfg: &mut SimConfig, nodes: &[usize]) {
    for &node in nodes {
        add_caps(cfg, node, Capabilities::LOW_ENERGY);
        cfg.node_types[node] = NodeType::Sensor;
        cfg.node_behaviors[node].scan = false;
        cfg.node_behaviors[node].initiate_h2h = false;
    }
}

fn assign_routing(cfg: &mut SimConfig, nodes: &[usize]) {
    for &node in nodes {
        add_caps(cfg, node, Capabilities::ROUTE | Capabilities::STORE);
        cfg.node_types[node] = NodeType::Router;
        cfg.node_behaviors[node] = NodeBehavior::default();
    }
}

fn assign_application(cfg: &mut SimConfig, nodes: &[usize]) {
    for &node in nodes {
        add_caps(cfg, node, Capabilities::APPLICATION);
        if cfg.node_types[node] == NodeType::Sensor {
            cfg.node_types[node] = NodeType::FullNode;
        }
        cfg.node_behaviors[node].emit_sensor = true;
    }
}

fn assign_bridge(cfg: &mut SimConfig, node: usize) {
    add_caps(
        cfg,
        node,
        Capabilities::ROUTE | Capabilities::BRIDGE | Capabilities::STORE,
    );
    cfg.node_types[node] = NodeType::Gateway;
    cfg.node_behaviors[node] = NodeBehavior::default();
}

fn assign_mobile(cfg: &mut SimConfig, nodes: &[usize]) {
    for &node in nodes {
        add_caps(cfg, node, Capabilities::MOBILE);
        cfg.node_behaviors[node].scan = true;
        cfg.node_behaviors[node].initiate_h2h = true;
    }
}

fn add_caps(cfg: &mut SimConfig, node: usize, flags: u16) {
    cfg.capabilities[node] |= flags;
}

fn enable_bidirectional_link(cfg: &mut SimConfig, a: usize, b: usize) {
    cfg.link_enabled[a][b] = true;
    cfg.link_enabled[b][a] = true;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_role(cfg: &SimConfig, flag: u16) -> usize {
        cfg.capabilities[..cfg.n_active]
            .iter()
            .filter(|bits| (**bits & flag) != 0)
            .count()
    }

    fn count_routing_excluding_bridge(cfg: &SimConfig) -> usize {
        cfg.capabilities[..cfg.n_active]
            .iter()
            .filter(|bits| {
                (**bits & Capabilities::ROUTE) != 0 && (**bits & Capabilities::BRIDGE) == 0
            })
            .count()
    }

    #[test]
    fn partitioned_bridge_has_bridge_corridor() {
        let cfg = build_config(ScenarioId::PartitionedBridge);

        assert_eq!(cfg.n_active, 18);
        assert!(cfg.link_enabled[2][15]);
        assert!(cfg.link_enabled[15][3]);
        assert!(!cfg.link_enabled[1][14]);
        assert_eq!(count_role(&cfg, Capabilities::BRIDGE), 1);
    }

    #[test]
    fn field_deployment_matches_requested_role_ranges() {
        let cfg = build_config(ScenarioId::FieldDeployment);

        assert!((5..=20).contains(&count_role(&cfg, Capabilities::LOW_ENERGY)));
        assert!((1..=5).contains(&count_routing_excluding_bridge(&cfg)));
        assert!((0..=2).contains(&count_role(&cfg, Capabilities::APPLICATION)));
        assert!((0..=1).contains(&count_role(&cfg, Capabilities::BRIDGE)));
        assert!((1..=2).contains(&count_role(&cfg, Capabilities::MOBILE)));
    }
}
