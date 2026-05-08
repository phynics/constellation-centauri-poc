use std::time::Duration;

use serial_test::serial;
use sim::harness::{SimHarness, BROADCAST_NODE};
use sim::scenario;
use sim::sim_state::{MessageKind, TraceStatus};

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
