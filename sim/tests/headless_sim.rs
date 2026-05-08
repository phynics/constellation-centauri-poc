use std::time::Duration;

use serial_test::serial;
use sim::harness::{SimHarness, BROADCAST_NODE};
use sim::scenario;
use sim::sim_state::{MessageKind, TraceEventKind, TraceStatus};

fn forwarded_edges(trace: &sim::sim_state::MessageTrace) -> Vec<(usize, usize)> {
    trace
        .events
        .iter()
        .filter_map(|event| match event.kind {
            TraceEventKind::Forwarded { to_node } => Some((event.node_idx, to_node)),
            _ => None,
        })
        .collect()
}

#[test]
#[serial]
fn partitioned_bridge_routes_across_bridge_corridor() {
    let sim = SimHarness::new(scenario::partitioned_bridge_deterministic());
    sim.seed_all_direct_links();
    sim.seed_indirect_peer_via(2, 15, 3, 1, 2);

    let trace_id = sim.send_message(2, 3, MessageKind::Manual, "cross-bridge");
    let trace = sim.wait_for_trace_terminal(trace_id, Duration::from_secs(2));

    assert_eq!(forwarded_edges(&trace), vec![(2, 15), (15, 3)]);
    assert!(trace
        .events
        .iter()
        .any(|event| { matches!(event.kind, TraceEventKind::Delivered) && event.node_idx == 3 }));
}

#[test]
#[serial]
fn partitioned_bridge_reports_no_route_when_bridge_corridor_is_disabled() {
    let sim = SimHarness::new(scenario::partitioned_bridge_deterministic());
    sim.seed_all_direct_links();
    sim.seed_indirect_peer_via(2, 15, 3, 1, 2);
    sim.update_config(|cfg| sim::config_ops::set_link_enabled(cfg, 15, 3, false));

    let trace_id = sim.send_message(2, 3, MessageKind::Manual, "blocked-bridge");
    let trace = sim.wait_for_trace_terminal(trace_id, Duration::from_secs(2));

    assert_eq!(trace.terminal_status, TraceStatus::NoRoute);
    assert!(trace.events.iter().any(|event| {
        matches!(event.kind, TraceEventKind::Blocked { to_node: 3 }) && event.node_idx == 15
    }));
}

#[test]
#[serial]
fn full_mesh_broadcast_reaches_all_active_nodes() {
    let sim = SimHarness::new(scenario::full_mesh_small(5));

    sim.seed_all_direct_links();

    let trace_id = sim.send_message(0, BROADCAST_NODE, MessageKind::Manual, "broadcast");
    let trace = sim.wait_for_trace_terminal(trace_id, Duration::from_secs(3));
    let cfg = sim.config();

    assert!(matches!(
        trace.terminal_status,
        TraceStatus::Delivered | TraceStatus::Deduped
    ));

    let source_forward_count = trace
        .events
        .iter()
        .filter(|event| {
            matches!(event.kind, TraceEventKind::Forwarded { .. }) && event.node_idx == 0
        })
        .count();
    assert_eq!(source_forward_count, cfg.n_active - 1);

    let mut observed = vec![false; cfg.n_active];
    for event in &trace.events {
        if matches!(event.kind, TraceEventKind::ObservedBroadcast) && event.node_idx < cfg.n_active
        {
            observed[event.node_idx] = true;
        }
    }

    assert!(observed.iter().filter(|seen| **seen).count() >= cfg.n_active - 1);
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
    let blocked_trace = sim.wait_for_trace_terminal(blocked_trace_id, Duration::from_secs(2));
    assert_eq!(blocked_trace.terminal_status, TraceStatus::NoRoute);

    sim.schedule_bidirectional_link(Duration::from_millis(150), 15, 3, true);
    std::thread::sleep(Duration::from_millis(250));

    let healed_trace_id = sim.send_message(2, 3, MessageKind::Manual, "after-heal");
    let healed_trace = sim.wait_for_trace_terminal(healed_trace_id, Duration::from_secs(2));

    assert!(matches!(
        healed_trace.terminal_status,
        TraceStatus::Delivered | TraceStatus::Deduped
    ));
    assert_eq!(forwarded_edges(&healed_trace), vec![(2, 15), (15, 3)]);
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
    let blocked_trace = sim.wait_for_trace_terminal(blocked_trace_id, Duration::from_secs(2));
    assert_eq!(blocked_trace.terminal_status, TraceStatus::NoRoute);

    sim.schedule_link_enabled(Duration::from_millis(120), 2, 3, true);
    std::thread::sleep(Duration::from_millis(220));

    let recovered_trace_id = sim.send_message(0, 3, MessageKind::Manual, "edge-up");
    let recovered_trace = sim.wait_for_trace_terminal(recovered_trace_id, Duration::from_secs(2));

    assert!(matches!(
        recovered_trace.terminal_status,
        TraceStatus::Delivered | TraceStatus::Deduped
    ));
    assert_eq!(forwarded_edges(&recovered_trace), vec![(0, 2), (2, 3)]);
}
