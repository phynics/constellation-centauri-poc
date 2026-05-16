//! Simulator diagnostic export helpers.
//!
//! Purpose: serialize simulator state, traces, and scenario context into host
//! files for offline inspection.
//!
//! Design decisions:
//! - Keep export formatting and filesystem concerns in `sim`, not in shared
//!   protocol crates.
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::scenario::{ScenarioId, ScenarioPreset};
use crate::sim_state::{
    MessageTrace, NodeBehavior, NodeSnapshot, NodeType, SimConfig, TraceEvent, TraceEventKind,
    TraceFilter, TraceStatus, TuiState, MAX_NODES,
};

pub struct ExportContext<'a> {
    pub scenario: &'a ScenarioPreset,
    pub trace_filter: TraceFilter,
    pub selected_trace_index: usize,
    pub logs: &'a [String],
}

pub fn export_diagnostics(
    state: &TuiState,
    config: &SimConfig,
    ctx: ExportContext<'_>,
) -> io::Result<PathBuf> {
    let export_dir = std::env::current_dir()?.join("sim-exports");
    export_diagnostics_to_dir(state, config, ctx, &export_dir)
}

fn export_diagnostics_to_dir(
    state: &TuiState,
    config: &SimConfig,
    ctx: ExportContext<'_>,
    export_dir: &Path,
) -> io::Result<PathBuf> {
    fs::create_dir_all(export_dir)?;

    let export_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = export_dir.join(format!("sim-diagnostics-{export_id}.json"));
    let contents = render_export_json(state, config, ctx)?;
    fs::write(&path, contents)?;
    Ok(path)
}

fn render_export_json(
    state: &TuiState,
    config: &SimConfig,
    ctx: ExportContext<'_>,
) -> io::Result<String> {
    let bundle = build_export_bundle(state, config, ctx);
    serde_json::to_string_pretty(&bundle)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("json export failed: {err}")))
}

fn build_export_bundle(
    state: &TuiState,
    config: &SimConfig,
    ctx: ExportContext<'_>,
) -> DiagnosticExport {
    let selected_trace_id =
        selected_trace(state, ctx.trace_filter, ctx.selected_trace_index).map(|trace| trace.id);

    DiagnosticExport {
        export_format: "constellation-sim-diagnostics/v1",
        exported_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        session: SessionExport {
            elapsed_secs: state.elapsed_secs,
            current_scenario: ScenarioExport::from_preset(ctx.scenario),
            selection: SelectionExport {
                trace_filter: trace_filter_name(ctx.trace_filter),
                selected_trace_index: ctx.selected_trace_index,
                selected_trace_id,
            },
        },
        sim_config: SimConfigExport::from_config(config),
        runtime_state: RuntimeStateExport::from_state(state),
        traces: state.traces.iter().map(TraceExport::from_trace).collect(),
        logs: ctx.logs.to_vec(),
    }
}

fn selected_trace(
    state: &TuiState,
    trace_filter: TraceFilter,
    selected_trace_index: usize,
) -> Option<&MessageTrace> {
    let filtered = state.filtered_trace_indices(trace_filter);
    filtered
        .get(selected_trace_index)
        .and_then(|idx| state.traces.get(*idx))
}

fn trace_filter_name(filter: TraceFilter) -> &'static str {
    match filter {
        TraceFilter::All => "all",
        TraceFilter::Directed => "directed",
        TraceFilter::Broadcast => "broadcast",
    }
}

fn scenario_id_name(id: ScenarioId) -> &'static str {
    match id {
        ScenarioId::FullMeshBaseline => "full-mesh-baseline",
        ScenarioId::PartitionedBridge => "partitioned-bridge",
        ScenarioId::LossyEdge => "lossy-edge",
        ScenarioId::FieldDeployment => "field-deployment",
    }
}

fn node_type_name(node_type: NodeType) -> &'static str {
    match node_type {
        NodeType::FullNode => "full-node",
        NodeType::Router => "router",
        NodeType::Sensor => "sensor",
        NodeType::Gateway => "gateway",
    }
}

fn trace_status_name(status: TraceStatus) -> &'static str {
    match status {
        TraceStatus::Pending => "pending",
        TraceStatus::Delivered => "delivered",
        TraceStatus::NoRoute => "no-route",
        TraceStatus::TtlExpired => "ttl-expired",
        TraceStatus::Dropped => "dropped",
        TraceStatus::Deduped => "deduped",
    }
}

fn trace_event_kind_export(kind: &TraceEventKind) -> TraceEventKindExport {
    match kind {
        TraceEventKind::Queued => TraceEventKindExport {
            name: "queued",
            from_node: None,
            to_node: None,
        },
        TraceEventKind::Deferred => TraceEventKindExport {
            name: "deferred",
            from_node: None,
            to_node: None,
        },
        TraceEventKind::Received { from_node } => TraceEventKindExport {
            name: "received",
            from_node: Some(*from_node),
            to_node: None,
        },
        TraceEventKind::ObservedBroadcast => TraceEventKindExport {
            name: "observed-broadcast",
            from_node: None,
            to_node: None,
        },
        TraceEventKind::Forwarded { to_node } => TraceEventKindExport {
            name: "forwarded",
            from_node: None,
            to_node: Some(*to_node),
        },
        TraceEventKind::LpnWakeSync { router_node } => TraceEventKindExport {
            name: "lpn-wake-sync",
            from_node: None,
            to_node: Some(*router_node),
        },
        TraceEventKind::PendingAnnounced { .. } => TraceEventKindExport {
            name: "pending-announced",
            from_node: None,
            to_node: None,
        },
        TraceEventKind::DeliveredFromStore { router_node } => TraceEventKindExport {
            name: "delivered-from-store",
            from_node: Some(*router_node),
            to_node: None,
        },
        TraceEventKind::DeliveryConfirmed { lpn_node } => TraceEventKindExport {
            name: "delivery-confirmed",
            from_node: None,
            to_node: Some(*lpn_node),
        },
        TraceEventKind::ExpiredFromStore => TraceEventKindExport {
            name: "expired-from-store",
            from_node: None,
            to_node: None,
        },
        TraceEventKind::Delivered => TraceEventKindExport {
            name: "delivered",
            from_node: None,
            to_node: None,
        },
        TraceEventKind::Dropped { to_node } => TraceEventKindExport {
            name: "dropped",
            from_node: None,
            to_node: *to_node,
        },
        TraceEventKind::Blocked { to_node } => TraceEventKindExport {
            name: "blocked",
            from_node: None,
            to_node: Some(*to_node),
        },
        TraceEventKind::NoRoute => TraceEventKindExport {
            name: "no-route",
            from_node: None,
            to_node: None,
        },
        TraceEventKind::Deduped => TraceEventKindExport {
            name: "deduped",
            from_node: None,
            to_node: None,
        },
        TraceEventKind::TtlExpired => TraceEventKindExport {
            name: "ttl-expired",
            from_node: None,
            to_node: None,
        },
    }
}

#[derive(Serialize)]
struct DiagnosticExport {
    export_format: &'static str,
    exported_at_unix_secs: u64,
    session: SessionExport,
    sim_config: SimConfigExport,
    runtime_state: RuntimeStateExport,
    traces: Vec<TraceExport>,
    logs: Vec<String>,
}

#[derive(Serialize)]
struct SessionExport {
    elapsed_secs: u32,
    current_scenario: ScenarioExport,
    selection: SelectionExport,
}

#[derive(Serialize)]
struct ScenarioExport {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    expected_outcome: &'static str,
}

impl ScenarioExport {
    fn from_preset(preset: &ScenarioPreset) -> Self {
        Self {
            id: scenario_id_name(preset.id),
            name: preset.name,
            description: preset.description,
            expected_outcome: preset.expected_outcome,
        }
    }
}

#[derive(Serialize)]
struct SelectionExport {
    trace_filter: &'static str,
    selected_trace_index: usize,
    selected_trace_id: Option<u64>,
}

#[derive(Serialize)]
struct SimConfigExport {
    n_active: usize,
    sensor_auto: bool,
    sensor_interval_secs: u64,
    nodes: Vec<ConfigNodeExport>,
    link_enabled: Vec<Vec<bool>>,
    drop_prob: Vec<Vec<u8>>,
}

impl SimConfigExport {
    fn from_config(config: &SimConfig) -> Self {
        Self {
            n_active: config.n_active,
            sensor_auto: config.sensor_auto,
            sensor_interval_secs: config.sensor_interval_secs,
            nodes: (0..MAX_NODES)
                .map(|idx| ConfigNodeExport {
                    node_idx: idx,
                    active: idx < config.n_active,
                    capabilities: config.capabilities[idx],
                    node_type: node_type_name(config.node_types[idx]),
                    behavior: NodeBehaviorExport::from_behavior(config.node_behaviors[idx]),
                })
                .collect(),
            link_enabled: config.link_enabled.iter().map(|row| row.to_vec()).collect(),
            drop_prob: config.drop_prob.iter().map(|row| row.to_vec()).collect(),
        }
    }
}

#[derive(Serialize)]
struct ConfigNodeExport {
    node_idx: usize,
    active: bool,
    capabilities: u16,
    node_type: &'static str,
    behavior: NodeBehaviorExport,
}

#[derive(Serialize)]
struct NodeBehaviorExport {
    advertise: bool,
    scan: bool,
    initiate_h2h: bool,
    respond_h2h: bool,
    emit_sensor: bool,
}

impl NodeBehaviorExport {
    fn from_behavior(behavior: NodeBehavior) -> Self {
        Self {
            advertise: behavior.advertise,
            scan: behavior.scan,
            initiate_h2h: behavior.initiate_h2h,
            respond_h2h: behavior.respond_h2h,
            emit_sensor: behavior.emit_sensor,
        }
    }
}

#[derive(Serialize)]
struct RuntimeStateExport {
    elapsed_secs: u32,
    next_trace_id: u64,
    msgs_sent: Vec<u32>,
    msgs_received: Vec<u32>,
    node_short_addrs: Vec<[u8; 8]>,
    nodes: Vec<NodeSnapshotExport>,
}

impl RuntimeStateExport {
    fn from_state(state: &TuiState) -> Self {
        Self {
            elapsed_secs: state.elapsed_secs,
            next_trace_id: state.next_trace_id,
            msgs_sent: state.msgs_sent.to_vec(),
            msgs_received: state.msgs_received.to_vec(),
            node_short_addrs: state.node_short_addrs.to_vec(),
            nodes: state
                .nodes
                .iter()
                .enumerate()
                .map(|(idx, node)| NodeSnapshotExport::from_snapshot(idx, node))
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct NodeSnapshotExport {
    node_idx: usize,
    active: bool,
    short_addr: [u8; 8],
    uptime_secs: u32,
    capabilities: u16,
    node_type: &'static str,
    peers: Vec<PeerSnapshotExport>,
}

impl NodeSnapshotExport {
    fn from_snapshot(node_idx: usize, node: &NodeSnapshot) -> Self {
        Self {
            node_idx,
            active: node.active,
            short_addr: node.short_addr,
            uptime_secs: node.uptime_secs,
            capabilities: node.capabilities,
            node_type: node_type_name(node.node_type),
            peers: node
                .peers
                .iter()
                .map(|peer| PeerSnapshotExport {
                    short_addr: peer.short_addr,
                    trust: peer.trust,
                    hop_count: peer.hop_count,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct PeerSnapshotExport {
    short_addr: [u8; 8],
    trust: u8,
    hop_count: u8,
}

#[derive(Serialize)]
struct TraceExport {
    id: u64,
    created_secs: u32,
    delivered_secs: Option<u32>,
    from_idx: usize,
    to_idx: usize,
    kind: &'static str,
    body: String,
    source_caps: u16,
    target_caps: u16,
    packet_type: u8,
    packet_flags: u8,
    dst_addr: [u8; 8],
    is_broadcast: bool,
    link_enabled_at_send: bool,
    drop_prob_at_send: u8,
    message_id: [u8; 8],
    ttl_at_send: u8,
    terminal_status: &'static str,
    events: Vec<TraceEventExport>,
}

impl TraceExport {
    fn from_trace(trace: &MessageTrace) -> Self {
        Self {
            id: trace.id,
            created_secs: trace.created_secs,
            delivered_secs: trace.delivered_secs,
            from_idx: trace.from_idx,
            to_idx: trace.to_idx,
            kind: trace.kind.as_str(),
            body: trace.body.clone(),
            source_caps: trace.source_caps,
            target_caps: trace.target_caps,
            packet_type: trace.packet_type,
            packet_flags: trace.packet_flags,
            dst_addr: trace.dst_addr,
            is_broadcast: trace.is_broadcast,
            link_enabled_at_send: trace.link_enabled_at_send,
            drop_prob_at_send: trace.drop_prob_at_send,
            message_id: trace.message_id,
            ttl_at_send: trace.ttl_at_send,
            terminal_status: trace_status_name(trace.terminal_status),
            events: trace
                .events
                .iter()
                .map(TraceEventExport::from_event)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct TraceEventExport {
    time_secs: u32,
    node_idx: usize,
    ttl: u8,
    hop_count: u8,
    kind: TraceEventKindExport,
    description: String,
    message: String,
}

impl TraceEventExport {
    fn from_event(event: &TraceEvent) -> Self {
        Self {
            time_secs: event.time_secs,
            node_idx: event.node_idx,
            ttl: event.ttl,
            hop_count: event.hop_count,
            kind: trace_event_kind_export(&event.kind),
            description: event
                .kind
                .describe(event.node_idx, event.ttl, event.hop_count),
            message: event.message.clone(),
        }
    }
}

#[derive(Serialize)]
struct TraceEventKindExport {
    name: &'static str,
    from_node: Option<usize>,
    to_node: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::{render_export_json, ExportContext};
    use crate::scenario::{build_config, preset, ScenarioId};
    use crate::sim_state::{MessageKind, TraceEventKind, TraceFilter, TuiState, MAX_NODES};

    #[test]
    fn export_contains_all_config_traces_and_logs() {
        let mut state = TuiState {
            elapsed_secs: 42,
            ..TuiState::default()
        };
        let mut config = build_config(ScenarioId::FullMeshBaseline);
        config.sensor_auto = true;
        config.drop_prob[1][2] = 33;
        config.link_enabled[1][2] = false;

        let directed_trace = state.create_trace(
            1,
            2,
            MessageKind::Manual,
            "hello mesh".to_string(),
            0x0003,
            0x0004,
            0x42,
            0b0000_0011,
            [0x11; 8],
            false,
            false,
            33,
            [0xaa; 8],
            6,
        );
        state.push_trace_event(
            directed_trace,
            1,
            5,
            1,
            TraceEventKind::Forwarded { to_node: 2 },
            "forwarded toward node 2",
        );
        state.mark_trace_delivered(directed_trace);
        state.push_trace_event(
            directed_trace,
            2,
            5,
            1,
            TraceEventKind::Delivered,
            "delivered locally",
        );

        let broadcast_trace = state.create_trace(
            0,
            MAX_NODES,
            MessageKind::Manual,
            "broadcast".to_string(),
            0,
            0,
            0x01,
            0,
            [0; 8],
            true,
            true,
            0,
            [0xbb; 8],
            4,
        );
        state.push_trace_event(
            broadcast_trace,
            3,
            3,
            1,
            TraceEventKind::ObservedBroadcast,
            "observed broadcast",
        );

        let logs = vec![
            "[INFO ] Scenario applied: Full mesh baseline".to_string(),
            "[WARN ] synthetic warning".to_string(),
        ];

        let json = render_export_json(
            &state,
            &config,
            ExportContext {
                scenario: preset(ScenarioId::FullMeshBaseline),
                trace_filter: TraceFilter::All,
                selected_trace_index: 0,
                logs: &logs,
            },
        )
        .expect("json export should render");

        assert!(json.contains("\"export_format\": \"constellation-sim-diagnostics/v1\""));
        assert!(json.contains("\"selected_trace_id\": 1"));
        assert!(json.contains("\"sensor_auto\": true"));
        assert!(json.contains("\"drop_prob\""));
        assert!(json.contains("\"link_enabled\""));
        assert!(json.contains("\"traces\""));
        assert!(json.contains("\"body\": \"hello mesh\""));
        assert!(json.contains("\"body\": \"broadcast\""));
        assert!(json.contains("\"name\": \"observed-broadcast\""));
        assert!(json.contains("\"logs\""));
        assert!(json.contains("synthetic warning"));
    }

    #[test]
    fn export_reports_missing_selected_trace_cleanly() {
        let state = TuiState::default();
        let config = build_config(ScenarioId::PartitionedBridge);
        let json = render_export_json(
            &state,
            &config,
            ExportContext {
                scenario: preset(ScenarioId::PartitionedBridge),
                trace_filter: TraceFilter::All,
                selected_trace_index: 0,
                logs: &[],
            },
        )
        .expect("json export should render");

        assert!(json.contains("\"selected_trace_id\": null"));
        assert!(json.contains("\"traces\": []"));
        assert!(json.contains("\"logs\": []"));
    }
}
