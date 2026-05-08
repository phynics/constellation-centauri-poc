use std::time::Duration;

use serial_test::serial;
use sim::harness::{SimHarness, BROADCAST_NODE};
use sim::scenario;
use sim::sim_state::{MessageKind, TraceEventKind, TraceStatus};

#[test]
#[serial]
fn partitioned_bridge_routes_across_bridge_corridor() {
    let sim = SimHarness::new(scenario::partitioned_bridge_deterministic());
    sim.seed_all_direct_links();
    sim.seed_indirect_peer_via(2, 15, 3, 1, 2);

    let trace_id = sim.send_message(2, 3, MessageKind::Manual, "cross-bridge");
    sim.wait_for_trace_terminal(trace_id, Duration::from_secs(2));

    sim.assert_forwarded_edges(trace_id, &[(2, 15), (15, 3)]);
    sim.assert_delivered_to(trace_id, 3);
}

#[test]
#[serial]
fn partitioned_bridge_reports_no_route_when_bridge_corridor_is_disabled() {
    let sim = SimHarness::new(scenario::partitioned_bridge_deterministic());
    sim.seed_all_direct_links();
    sim.seed_indirect_peer_via(2, 15, 3, 1, 2);
    sim.update_config(|cfg| sim::config_ops::set_link_enabled(cfg, 15, 3, false));

    let trace_id = sim.send_message(2, 3, MessageKind::Manual, "blocked-bridge");
    sim.wait_for_trace_terminal(trace_id, Duration::from_secs(2));

    sim.assert_terminal_status_one_of(trace_id, &[TraceStatus::NoRoute]);
    sim.assert_blocked_edge(trace_id, 15, 3);
}

#[test]
#[serial]
fn full_mesh_broadcast_reaches_all_active_nodes() {
    let sim = SimHarness::new(scenario::full_mesh_small(5));

    sim.seed_all_direct_links();

    let trace_id = sim.send_message(0, BROADCAST_NODE, MessageKind::Manual, "broadcast");
    sim.wait_for_trace_terminal(trace_id, Duration::from_secs(3));
    let cfg = sim.config();

    sim.assert_terminal_status_one_of(trace_id, &[TraceStatus::Delivered, TraceStatus::Deduped]);

    let source_forward_count = sim
        .forwarded_edges(trace_id)
        .iter()
        .filter(|(from, _)| *from == 0)
        .count();
    assert_eq!(source_forward_count, cfg.n_active - 1);
    sim.assert_broadcast_observed_by_at_least(trace_id, cfg.n_active - 1);
}

#[test]
#[serial]
fn partitioned_bridge_recovers_delivery_after_timed_heal() {
    let sim = SimHarness::new(scenario::partitioned_bridge_deterministic());
    sim.seed_all_direct_links();
    sim.seed_indirect_peer_via(2, 15, 3, 1, 2);
    sim.update_config(|cfg| {
        sim::config_ops::set_bidirectional_link(cfg, 15, 3, false);
    });

    let blocked_trace_id = sim.send_message(2, 3, MessageKind::Manual, "before-heal");
    sim.wait_for_trace_terminal(blocked_trace_id, Duration::from_secs(2));
    sim.assert_terminal_status_one_of(blocked_trace_id, &[TraceStatus::NoRoute]);

    sim.schedule_bidirectional_link(Duration::from_millis(150), 15, 3, true);
    std::thread::sleep(Duration::from_millis(250));

    let healed_trace_id = sim.send_message(2, 3, MessageKind::Manual, "after-heal");
    sim.wait_for_trace_terminal(healed_trace_id, Duration::from_secs(2));

    sim.assert_terminal_status_one_of(
        healed_trace_id,
        &[TraceStatus::Delivered, TraceStatus::Deduped],
    );
    sim.assert_forwarded_edges(healed_trace_id, &[(2, 15), (15, 3)]);
}

#[test]
#[serial]
fn field_deployment_low_power_endpoints_converge_to_routers() {
    let sim = SimHarness::from_scenario(sim::scenario::ScenarioId::FieldDeployment);

    // Wait for two H2H cycles to allow discovery + uplink convergence.
    std::thread::sleep(Duration::from_secs(140));

    let state = sim.state();
    let cfg = sim.config();

    // Count how many LE endpoints (LOW_ENERGY and not ROUTE) have at least
    // one direct peer. Before the uplink H2H fix, these nodes sat at
    // peer_count = 0 despite being directly linked to routers.
    let mut le_with_peers = 0;
    let mut le_total = 0;
    for i in 0..cfg.n_active {
        let caps = cfg.capabilities[i];
        let is_le = caps & routing_core::node::roles::Capabilities::LOW_ENERGY != 0
            && caps & routing_core::node::roles::Capabilities::ROUTE == 0;
        if !is_le {
            continue;
        }
        le_total += 1;
        if !state.nodes[i].peers.is_empty() {
            le_with_peers += 1;
        }
    }

    assert!(
        le_with_peers > 0,
        "no low-power endpoints have peers after 140s ({} LE endpoints checked)",
        le_total
    );
}

#[test]
#[serial]
fn lossy_edge_mobile_link_toggle_recovers_delivery() {
    let sim = SimHarness::new(scenario::lossy_edge_small_deterministic());

    sim.seed_direct_peer(0, 2, 1);
    sim.seed_direct_peer(2, 0, 1);
    sim.seed_direct_peer(2, 3, 1);
    sim.seed_indirect_peer_via(0, 2, 3, 1, 2);
    sim.update_config(|cfg| sim::config_ops::set_link_enabled(cfg, 2, 3, false));

    let blocked_trace_id = sim.send_message(0, 3, MessageKind::Manual, "edge-down");
    sim.wait_for_trace_terminal(blocked_trace_id, Duration::from_secs(2));
    sim.assert_terminal_status_one_of(blocked_trace_id, &[TraceStatus::NoRoute]);

    sim.schedule_link_enabled(Duration::from_millis(120), 2, 3, true);
    std::thread::sleep(Duration::from_millis(220));

    let recovered_trace_id = sim.send_message(0, 3, MessageKind::Manual, "edge-up");
    sim.wait_for_trace_terminal(recovered_trace_id, Duration::from_secs(2));

    sim.assert_terminal_status_one_of(
        recovered_trace_id,
        &[TraceStatus::Delivered, TraceStatus::Deduped],
    );
    sim.assert_forwarded_edges(recovered_trace_id, &[(0, 2), (2, 3)]);
}

#[test]
#[serial]
fn low_power_endpoint_collects_retained_delivery_on_wake_h2h() {
    let mut cfg = sim::sim_state::SimConfig::default();
    cfg.n_active = 2;
    cfg.capabilities[0] = routing_core::node::roles::Capabilities::ROUTE
        | routing_core::node::roles::Capabilities::STORE;
    cfg.capabilities[1] = routing_core::node::roles::Capabilities::LOW_ENERGY
        | routing_core::node::roles::Capabilities::APPLICATION;
    cfg.node_behaviors[1].scan = false;
    cfg.node_behaviors[1].initiate_h2h = false;
    cfg.link_enabled[0][1] = false;
    cfg.link_enabled[1][0] = false;

    let sim = SimHarness::new(cfg);
    let trace_id = sim.send_message(0, 1, MessageKind::Manual, "retained wake delivery");

    // Allow the initial send to be retained first, then re-enable the link so
    // the low-power endpoint can discover the router during its next wake scan.
    sim.schedule_bidirectional_link(Duration::from_secs(1), 0, 1, true);

    let trace = sim.wait_for_trace_terminal(trace_id, Duration::from_secs(20));
    assert_eq!(trace.terminal_status, TraceStatus::Delivered);
    assert!(trace.events.iter().any(|event| matches!(event.kind, TraceEventKind::Deferred)));
    assert!(trace.events.iter().any(|event| {
        matches!(event.kind, TraceEventKind::PendingAnnounced { .. })
    }));
    assert!(trace.events.iter().any(|event| {
        matches!(event.kind, TraceEventKind::DeliveredFromStore { .. })
    }));
    assert!(trace.events.iter().any(|event| {
        matches!(event.kind, TraceEventKind::DeliveryConfirmed { .. })
    }));
}

#[test]
#[serial]
fn low_power_endpoint_falls_back_to_backup_router_when_primary_is_unreachable() {
    let mut cfg = sim::sim_state::SimConfig::default();
    cfg.n_active = 3;
    cfg.capabilities[0] = routing_core::node::roles::Capabilities::ROUTE
        | routing_core::node::roles::Capabilities::STORE;
    cfg.capabilities[1] = routing_core::node::roles::Capabilities::ROUTE
        | routing_core::node::roles::Capabilities::STORE;
    cfg.capabilities[2] = routing_core::node::roles::Capabilities::LOW_ENERGY
        | routing_core::node::roles::Capabilities::APPLICATION;

    // Only the backup router remains reachable from the LPN during the wake.
    cfg.link_enabled[2][0] = false;
    cfg.link_enabled[0][2] = false;
    cfg.link_enabled[2][1] = true;
    cfg.link_enabled[1][2] = true;

    let sim = SimHarness::new(cfg);
    let trace_id = sim.send_message(0, 2, MessageKind::Manual, "fallback wake delivery");

    // Give the source router a retained trace, and seed a replica on the backup
    // router so this test focuses on the fallback wake behavior rather than the
    // replica seeding path itself.
    sim.seed_retained_delivery(trace_id, 0, 2, 0, 0, "fallback wake delivery");
    sim.seed_retained_delivery(trace_id, 0, 2, 1, 0, "fallback wake delivery");

    // The LPN prefers router 0 first (fresher timestamp) but must fall back to
    // router 1 because router 0 is unreachable in this wake window.
    sim.seed_direct_peer(2, 1, 1);
    sim.seed_direct_peer(2, 0, 2);

    let trace = sim.wait_for_trace_terminal(trace_id, Duration::from_secs(20));
    assert_eq!(trace.terminal_status, TraceStatus::Delivered);
    assert!(trace.events.iter().any(|event| matches!(event.kind, TraceEventKind::Deferred)));
    assert!(trace.events.iter().any(|event| {
        matches!(event.kind, TraceEventKind::DeliveredFromStore { router_node: 1 })
    }));
}
