use std::time::Duration;

use serial_test::serial;
use sim::harness::SimHarness;
use sim::sim_state::{MessageKind, TraceEventKind};

#[test]
#[serial]
#[ignore = "Known protocol deficiency: replay is accepted again after the dedup window rolls over"]
fn replayed_message_is_accepted_again_after_dedup_window_rollover() {
    let sim = SimHarness::new(sim::scenario::full_mesh_small(2));
    sim.seed_all_direct_links();

    let replay_id = [0xAA; 8];
    let first = sim.inject_message_with_id(0, 1, MessageKind::Manual, "replay me", replay_id);
    sim.wait_for_trace_terminal(first, Duration::from_secs(2));
    sim.assert_delivered_to(first, 1);

    for i in 0u8..=128 {
        let mut id = [0u8; 8];
        id[0] = i;
        id[7] = i.wrapping_mul(3);
        let trace_id = sim.inject_message_with_id(0, 1, MessageKind::Manual, format!("fill-{i}"), id);
        sim.wait_for_trace_terminal(trace_id, Duration::from_secs(2));
    }

    let replay = sim.inject_message_with_id(0, 1, MessageKind::Manual, "replay me again", replay_id);
    sim.wait_for_trace_terminal(replay, Duration::from_secs(2));

    // Desired property: old message IDs should remain non-replayable long
    // enough for the protocol's intended deployment model. Current behavior:
    // once the fixed in-memory ring rolls over, the replay is accepted again.
    assert_eq!(
        sim.trace_event_count(replay, |kind| matches!(kind, TraceEventKind::Deduped)),
        1,
        "replayed message was accepted again after dedup window rollover"
    );
}

#[test]
#[serial]
#[ignore = "Known protocol deficiency: retained-delivery queue overflow drops messages for sleeping low-power nodes"]
fn retained_delivery_queue_overflow_drops_messages_for_sleeping_low_power_nodes() {
    let mut cfg = sim::sim_state::SimConfig::default();
    cfg.n_active = 2;
    cfg.capabilities[0] = routing_core::node::roles::Capabilities::ROUTE
        | routing_core::node::roles::Capabilities::STORE;
    cfg.capabilities[1] = routing_core::node::roles::Capabilities::LOW_ENERGY
        | routing_core::node::roles::Capabilities::APPLICATION;
    cfg.link_enabled[0][1] = false;
    cfg.link_enabled[1][0] = false;

    let sim = SimHarness::new(cfg);
    let mut trace_ids = Vec::new();
    for i in 0..9 {
        let trace_id = sim.send_message(0, 1, MessageKind::Manual, format!("queued-{i}"));
        trace_ids.push(trace_id);
    }

    std::thread::sleep(Duration::from_millis(600));
    sim.update_config(|cfg| {
        sim::config_ops::set_bidirectional_link(cfg, 0, 1, true);
    });
    assert!(sim.run_h2h_session_with_peer(1, 0));
    std::thread::sleep(Duration::from_millis(600));

    let delivered = trace_ids
        .iter()
        .filter(|trace_id| {
            sim.trace_event_count(**trace_id, |kind| {
                matches!(kind, TraceEventKind::DeliveredFromStore { .. })
            }) > 0
        })
        .count();

    // Desired property: a sleeping low-power endpoint should not silently lose
    // retained messages because the local owner queue overflowed. Current
    // behavior: at least one message is dropped once the fixed per-holder queue
    // limit is exceeded.
    assert_eq!(
        delivered, 9,
        "retained-delivery queue overflow dropped at least one message before the endpoint woke"
    );
}

#[test]
#[serial]
#[ignore = "Known protocol deficiency: lost delivery ack causes duplicate redelivery on later wakes"]
fn missing_delivery_ack_causes_duplicate_redelivery_on_next_wake() {
    let mut cfg = sim::sim_state::SimConfig::default();
    cfg.n_active = 2;
    cfg.capabilities[0] = routing_core::node::roles::Capabilities::ROUTE
        | routing_core::node::roles::Capabilities::STORE;
    cfg.capabilities[1] = routing_core::node::roles::Capabilities::LOW_ENERGY
        | routing_core::node::roles::Capabilities::APPLICATION;
    cfg.link_enabled[0][1] = true;
    cfg.link_enabled[1][0] = true;
    cfg.node_behaviors[1].scan = false;
    cfg.node_behaviors[1].initiate_h2h = false;

    let sim = SimHarness::new(cfg);
    let trace_id = sim.send_message(0, 1, MessageKind::Manual, "deliver once only");
    sim.wait_for_retained_trace_at_holder(trace_id, 0, Duration::from_secs(2));

    assert!(sim.run_lpn_wake_without_delivery_ack(1, 0));
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        sim.retained_trace_exists_at_holder(trace_id, 0),
        "router should still retain the message after ack loss"
    );

    assert!(sim.run_h2h_session_with_peer(1, 0));
    std::thread::sleep(Duration::from_millis(300));

    // Desired property: a message already consumed by the LPN should not be
    // delivered again just because the ack was lost once. Current behavior:
    // the router redelivers it on the next wake because delivery state is not
    // robust against ack loss.
    assert_eq!(
        sim.trace_event_count(
            trace_id,
            |kind| matches!(kind, TraceEventKind::DeliveredFromStore { .. })
        ),
        1,
        "same retained payload was delivered again after a lost ack"
    );
}
