//! Trace-centric ratatui rendering.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

use routing_core::node::roles::Capabilities;

use super::app::{App, BottomTab, InputTarget, Mode, ViewMode};
use crate::scenario;
use crate::sim_state::{MessageTrace, SimConfig, TraceEventKind, TuiState, MAX_NODES};

pub fn render(frame: &mut Frame, app: &App, state: &TuiState, config: &SimConfig) {
    let area = frame.area();

    let vertical = Layout::vertical([
        Constraint::Length(4),
        Constraint::Fill(1),
        Constraint::Length(9),
    ])
    .split(area);

    let top = Layout::horizontal([
        Constraint::Length(42),
        Constraint::Fill(1),
        Constraint::Length(42),
    ])
    .split(vertical[1]);

    render_summary(frame, app, state, config, vertical[0]);
    match app.view_mode {
        ViewMode::Trace => {
            render_trace_list(frame, app, state, top[0]);
            render_trace_detail(frame, app, state, top[1]);
            let right =
                Layout::vertical([Constraint::Length(14), Constraint::Fill(1)]).split(top[2]);
            render_node_map(frame, app, state, config, right[0]);
            render_trace_context(frame, app, state, config, right[1]);
        }
        ViewMode::Nodes => {
            render_node_list(frame, app, state, config, top[0]);
            render_node_editor(frame, app, state, config, top[1]);
            render_node_context(frame, app, state, config, top[2]);
        }
        ViewMode::Links => {
            render_link_list(frame, app, config, top[0]);
            render_link_editor(frame, app, config, top[1]);
            render_node_map(frame, app, state, config, top[2]);
        }
    }
    render_bottom_panel(frame, app, state, vertical[2]);

    if app.mode == Mode::InputMessage {
        render_input_overlay(frame, app, area);
    }
    if app.mode == Mode::ScenarioSelect {
        render_scenario_overlay(frame, app, area);
    }
    if app.mode == Mode::Help {
        render_help_overlay(frame, area);
    }
}

fn render_summary(frame: &mut Frame, app: &App, state: &TuiState, config: &SimConfig, area: Rect) {
    let preset = app.current_scenario_preset();
    let selected = selected_trace(state, app);
    let block = Block::default()
        .title(" Trace debugger ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let trace_summary = if let Some(trace) = selected {
        format!(
            "selected=#{} {} {}→{} {}",
            trace.id,
            trace.kind.as_str(),
            trace.from_idx,
            trace.to_idx,
            trace.terminal_status.as_str()
        )
    } else {
        "selected=none".to_string()
    };

    let lines = vec![
        Line::styled(
            format!(" {}", preset.name),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!(" {}", preset.description)),
        Line::styled(
            format!(
                " mode={}  filter={}  traces={}  active={}  {}  [N] cycle modes  [F]ilter  [M] send  [R] scenario",
                match app.view_mode {
                    ViewMode::Trace => "trace",
                    ViewMode::Nodes => "nodes",
                    ViewMode::Links => "links",
                },
                app.trace_filter.as_str(),
                state.traces.len(),
                config.n_active,
                trace_summary
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_trace_list(frame: &mut Frame, app: &App, state: &TuiState, area: Rect) {
    let block = Block::default()
        .title(" Traces (↑↓ select) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let filtered = state.filtered_trace_indices(app.trace_filter);
    let visible = inner.height as usize;
    let total = filtered.len();
    let start = total.saturating_sub(visible).min(app.selected_trace);

    let items: Vec<ListItem> = filtered
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(idx, trace_idx)| {
            let trace = &state.traces[*trace_idx];
            let selected = idx == app.selected_trace;
            let style = if selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else if trace.delivered_secs.is_some() {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Yellow)
            };

            let label = format!(
                "#{:03} t={:>3}s {} {}→{} {:<9} {}",
                trace.id,
                trace.created_secs,
                trace.kind.as_str(),
                trace.from_idx,
                trace.to_idx,
                trace.terminal_status.as_str(),
                trace.body.chars().take(20).collect::<String>(),
            );

            ListItem::new(label).style(style)
        })
        .collect();

    frame.render_widget(List::new(items), inner);
}

fn render_trace_detail(frame: &mut Frame, app: &App, state: &TuiState, area: Rect) {
    let block = Block::default()
        .title(" Selected trace ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(trace) = selected_trace(state, app) else {
        frame.render_widget(
            Paragraph::new("No traces yet. Press [M] to inject a manual message.")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    };

    let lines = vec![
        Line::styled(
            format!("Trace #{}", trace.id),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!("Kind: {}", trace.kind.as_str())),
        Line::from(format!("Body: {}", trace.body)),
        Line::from(format!(
            "Source: node {} ({})",
            trace.from_idx,
            capability_long(trace.source_caps)
        )),
        Line::from(format!(
            "Target: node {} ({})",
            trace.to_idx,
            capability_long(trace.target_caps)
        )),
        Line::from(format!("Created: t={}s", trace.created_secs)),
        Line::from(format!(
            "Terminal status: {}",
            trace.terminal_status.as_str()
        )),
        Line::from(format!(
            "Delivered: {}",
            trace
                .delivered_secs
                .map(|secs| format!("t={}s", secs))
                .unwrap_or_else(|| "pending".to_string())
        )),
        Line::from(format!("Message ID: {:02x?}", trace.message_id)),
        Line::from(format!("TTL at send: {}", trace.ttl_at_send)),
        Line::from("Propagation model: routed hop-by-hop using routing-core candidates"),
        Line::raw(""),
        Line::styled(
            "Hop timeline",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    let mut lines = lines;
    for event in trace
        .events
        .iter()
        .rev()
        .take(inner.height.saturating_sub(lines.len() as u16) as usize)
        .rev()
    {
        lines.push(Line::from(format!(
            "  t={}s node {}: {}",
            event.time_secs, event.node_idx, event.message
        )));
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_node_list(
    frame: &mut Frame,
    app: &App,
    state: &TuiState,
    config: &SimConfig,
    area: Rect,
) {
    let block = Block::default()
        .title(" Nodes (↑↓ select) ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let items: Vec<ListItem> = (0..config.n_active)
        .map(|idx| {
            let selected = idx == app.selected_node;
            let style = if selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            let label = format!(
                "{:02} {:<8} caps={:<8} peers={:<2} {}",
                idx,
                config.node_types[idx].as_str(),
                capability_short(config.capabilities[idx]),
                state.nodes[idx].peers.len(),
                if state.nodes[idx].active {
                    "active"
                } else {
                    "inactive"
                }
            );
            ListItem::new(label).style(style)
        })
        .collect();

    frame.render_widget(List::new(items), inner);
}

fn render_node_editor(
    frame: &mut Frame,
    app: &App,
    state: &TuiState,
    config: &SimConfig,
    area: Rect,
) {
    let block = Block::default()
        .title(" Node editor ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.selected_node >= config.n_active {
        frame.render_widget(Paragraph::new("No active node selected."), inner);
        return;
    }

    let idx = app.selected_node;
    let behavior = config.node_behaviors[idx];
    let lines = vec![
        Line::styled(
            format!("Node {}", idx),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!("Type: {}", config.node_types[idx].as_str())),
        Line::from(format!(
            "Capabilities: {}",
            capability_long(config.capabilities[idx])
        )),
        Line::from(format!("Peers now: {}", state.nodes[idx].peers.len())),
        Line::from(format!("Uptime now: {}s", state.nodes[idx].uptime_secs)),
        Line::raw(""),
        Line::styled(
            "Capability toggles",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from("  [1] route  [2] store  [3] app  [4] bridge  [5] low-energy  [6] mobile"),
        Line::styled(
            "Behavior toggles",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!(
            "  [A] advertise={}  [C] scan={}  [I] initiate={}",
            on_off(behavior.advertise),
            on_off(behavior.scan),
            on_off(behavior.initiate_h2h)
        )),
        Line::from(format!(
            "  [O] respond={}   [E] emit_sensor={}",
            on_off(behavior.respond_h2h),
            on_off(behavior.emit_sensor)
        )),
        Line::from("  [T] cycle type  [Z] activate next node  [X] deactivate selected tail node"),
    ];

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_node_context(
    frame: &mut Frame,
    app: &App,
    state: &TuiState,
    config: &SimConfig,
    area: Rect,
) {
    let block = Block::default()
        .title(" Node context ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.selected_node >= config.n_active {
        frame.render_widget(Paragraph::new("No active node selected."), inner);
        return;
    }

    let idx = app.selected_node;
    let node = &state.nodes[idx];
    let mut lines = vec![Line::styled(
        "Known peers",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )];
    for peer in node
        .peers
        .iter()
        .take(inner.height.saturating_sub(6) as usize)
    {
        let peer_idx = state
            .nodes
            .iter()
            .position(|candidate| candidate.short_addr == peer.short_addr)
            .map(|i| i.to_string())
            .unwrap_or_else(|| "?".to_string());
        lines.push(Line::from(format!(
            " node {}  trust={} hop={} {:02x?}",
            peer_idx,
            peer.trust,
            peer.hop_count,
            &peer.short_addr[..4]
        )));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Edit notes",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ));
    lines.push(Line::from("Changes here update SimConfig directly."));
    lines.push(Line::from(
        "Use scenarios/H2H scans to see routing-core react.",
    ));

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_link_list(frame: &mut Frame, app: &App, config: &SimConfig, area: Rect) {
    let block = Block::default()
        .title(" Links (←→ node, ↑↓ peer) ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.selected_link_node >= config.n_active {
        frame.render_widget(Paragraph::new("No active node selected."), inner);
        return;
    }

    let items: Vec<ListItem> = (0..config.n_active)
        .filter(|peer| *peer != app.selected_link_node)
        .enumerate()
        .map(|(row, peer)| {
            let selected = row == app.selected_link_peer_row;
            let style = if selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            let label = format!(
                "{} → {}  {}  drop={}%",
                app.selected_link_node,
                peer,
                if config.link_enabled[app.selected_link_node][peer] {
                    "enabled "
                } else {
                    "disabled"
                },
                config.drop_prob[app.selected_link_node][peer]
            );
            ListItem::new(label).style(style)
        })
        .collect();

    frame.render_widget(List::new(items), inner);
}

fn render_link_editor(frame: &mut Frame, app: &App, config: &SimConfig, area: Rect) {
    let block = Block::default()
        .title(" Link editor ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some((from, to)) = selected_link_pair(app, config) else {
        frame.render_widget(Paragraph::new("No link selected."), inner);
        return;
    };

    let lines = vec![
        Line::styled(
            format!("{} → {}", from, to),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!(
            "Enabled: {}",
            on_off(config.link_enabled[from][to])
        )),
        Line::from(format!("Drop probability: {}%", config.drop_prob[from][to])),
        Line::raw(""),
        Line::from("[Space] toggle link"),
        Line::from("[P] set drop %"),
        Line::from("[←→] change source node"),
        Line::from("[↑↓] change peer row"),
    ];

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_node_map(frame: &mut Frame, app: &App, state: &TuiState, config: &SimConfig, area: Rect) {
    let block = Block::default()
        .title(" Visual node map ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width < 12 || inner.height < 8 {
        frame.render_widget(
            Paragraph::new("Map area too small.").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let selected_trace = selected_trace(state, app);
    let hop_nodes: Vec<usize> = selected_trace.map(trace_path_nodes).unwrap_or_default();

    let legend_height = 3u16;
    let map_height = inner.height.saturating_sub(legend_height).max(4);
    let map_area = Rect {
        x: inner.x,
        y: inner.y,
        width: inner.width,
        height: map_height,
    };
    let legend_area = Rect {
        x: inner.x,
        y: inner.y + map_height,
        width: inner.width,
        height: inner.height.saturating_sub(map_height),
    };

    let mut canvas = vec![vec![' '; map_area.width as usize]; map_area.height as usize];
    let mut styles =
        vec![vec![Style::default(); map_area.width as usize]; map_area.height as usize];
    let positions = node_positions(config.n_active, map_area.width, map_area.height);

    if let Some(trace) = selected_trace {
        for (from, to) in trace_hop_edges(trace) {
            if from < positions.len() && to < positions.len() {
                draw_link(
                    &mut canvas,
                    &mut styles,
                    positions[from],
                    positions[to],
                    if trace.is_broadcast {
                        Style::default().fg(Color::LightBlue)
                    } else {
                        Style::default().fg(Color::Green)
                    },
                );
            }
        }
    }

    for idx in 0..config.n_active {
        let (x, y) = positions[idx];
        let on_path = hop_nodes.contains(&idx);
        let is_src = selected_trace.map(|t| t.from_idx == idx).unwrap_or(false);
        let is_dst = selected_trace.map(|t| t.to_idx == idx).unwrap_or(false);
        let is_broadcast = selected_trace.map(|t| t.is_broadcast).unwrap_or(false);
        let marker = if is_src {
            'S'
        } else if is_broadcast && on_path {
            'B'
        } else if is_dst {
            'D'
        } else if on_path {
            '*'
        } else if idx == app.selected_node && app.view_mode == ViewMode::Nodes {
            '!'
        } else if idx == app.selected_link_node && app.view_mode == ViewMode::Links {
            '!'
        } else {
            'o'
        };
        let style = if idx == app.selected_node && app.view_mode == ViewMode::Nodes {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else if idx == app.selected_link_node && app.view_mode == ViewMode::Links {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if is_src {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else if is_dst {
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD)
        } else if is_broadcast && on_path {
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::BOLD)
        } else if on_path {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::White)
        };

        put_str(
            &mut canvas,
            &mut styles,
            x,
            y,
            &format!("{}{:02}", marker, idx),
            style,
        );
        if y + 1 < map_area.height as usize {
            put_str(
                &mut canvas,
                &mut styles,
                x,
                y + 1,
                &capability_short(config.capabilities[idx]),
                Style::default().fg(Color::DarkGray),
            );
        }
    }

    let map_lines: Vec<Line> = canvas
        .iter()
        .enumerate()
        .map(|(y, row)| {
            let spans = row
                .iter()
                .enumerate()
                .map(|(x, ch)| Span::styled(ch.to_string(), styles[y][x]))
                .collect::<Vec<_>>();
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(map_lines), map_area);

    let mut legend = vec![Line::styled(
        "S source  D dest  B broadcast-seen  * path  ! selected",
        Style::default().fg(Color::DarkGray),
    )];
    if let Some(trace) = selected_trace {
        legend.push(Line::from(trace_path_descriptions(trace).join(" -> ")));
    }
    frame.render_widget(
        Paragraph::new(legend).wrap(Wrap { trim: false }),
        legend_area,
    );
}

fn render_trace_context(
    frame: &mut Frame,
    app: &App,
    state: &TuiState,
    config: &SimConfig,
    area: Rect,
) {
    let block = Block::default()
        .title(" Trace context ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(trace) = selected_trace(state, app) else {
        frame.render_widget(
            Paragraph::new("Select a trace to inspect source/destination state.")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    };

    let src_node = &state.nodes[trace.from_idx.min(MAX_NODES - 1)];
    let (
        current_link,
        current_drop,
        dst_visible_from_src,
        dst_trust,
        dst_caps_now,
        dst_uptime_now,
        dst_peers_now,
    ) = if trace.is_broadcast {
        (
            true,
            0,
            "fan-out".to_string(),
            "n/a".to_string(),
            "broadcast".to_string(),
            0,
            0,
        )
    } else {
        let dst_node = &state.nodes[trace.to_idx.min(MAX_NODES - 1)];
        let dst_peer = src_node
            .peers
            .iter()
            .find(|peer| peer.short_addr == dst_node.short_addr);
        (
            config.link_enabled[trace.from_idx][trace.to_idx],
            config.drop_prob[trace.from_idx][trace.to_idx],
            dst_peer
                .map(|peer| {
                    if peer.hop_count == 0 {
                        "direct".to_string()
                    } else {
                        "indirect".to_string()
                    }
                })
                .unwrap_or_else(|| "not seen".to_string()),
            dst_peer
                .map(|peer| peer.trust.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            capability_long(dst_node.capabilities),
            dst_node.uptime_secs,
            dst_node.peers.len(),
        )
    };

    let lines = vec![
        Line::styled(
            "Send-time snapshot",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!(
            "Link enabled: {}",
            on_off(trace.link_enabled_at_send)
        )),
        Line::from(format!("Drop probability: {}%", trace.drop_prob_at_send)),
        Line::from(format!("Src caps: {}", capability_long(trace.source_caps))),
        Line::from(format!("Dst caps: {}", capability_long(trace.target_caps))),
        Line::raw(""),
        Line::styled(
            "Current context",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(format!("Current link enabled: {}", on_off(current_link))),
        Line::from(format!("Current drop probability: {}%", current_drop)),
        Line::from(format!("Src uptime now: {}s", src_node.uptime_secs)),
        Line::from(format!("Dst uptime now: {}s", dst_uptime_now)),
        Line::from(format!(
            "Src caps now: {}",
            capability_long(src_node.capabilities)
        )),
        Line::from(format!("Dst caps now: {}", dst_caps_now)),
        Line::from(format!("Src peers now: {}", src_node.peers.len())),
        Line::from(format!("Dst peers now: {}", dst_peers_now)),
        Line::from(format!("Dst visible from src: {}", dst_visible_from_src)),
        Line::from(format!("Dst trust from src: {}", dst_trust)),
        Line::raw(""),
        Line::styled(
            format!(
                "Src role={}  Dst role={}",
                capability_short(trace.source_caps),
                capability_short(trace.target_caps)
            ),
            Style::default().fg(Color::Cyan),
        ),
    ];

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_bottom_panel(frame: &mut Frame, app: &App, state: &TuiState, area: Rect) {
    let block = Block::default()
        .title(" Timeline / Logs ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let tab_style_active = Style::default().fg(Color::Black).bg(Color::Yellow);
    let tab_style_inactive = Style::default().fg(Color::DarkGray);

    let tab_area = Rect { height: 1, ..inner };
    let body_area = Rect {
        y: inner.y + 1,
        height: inner.height.saturating_sub(2),
        ..inner
    };
    let hint_area = Rect {
        y: inner.y + inner.height.saturating_sub(1),
        height: 1,
        ..inner
    };

    let timeline_style = if app.bottom_tab == BottomTab::Timeline {
        tab_style_active
    } else {
        tab_style_inactive
    };
    let graph_style = if app.bottom_tab == BottomTab::Graph {
        tab_style_active
    } else {
        tab_style_inactive
    };
    let packet_style = if app.bottom_tab == BottomTab::Packet {
        tab_style_active
    } else {
        tab_style_inactive
    };
    let logs_style = if app.bottom_tab == BottomTab::Logs {
        tab_style_active
    } else {
        tab_style_inactive
    };

    let tabs = Line::from(vec![
        Span::raw(" "),
        Span::styled(" Timeline ", timeline_style),
        Span::raw("  "),
        Span::styled(" Graph ", graph_style),
        Span::raw("  "),
        Span::styled(" Packet ", packet_style),
        Span::raw("  "),
        Span::styled(" Logs ", logs_style),
        Span::styled("   [G] switch", Style::default().fg(Color::DarkGray)),
    ]);
    frame.render_widget(Paragraph::new(tabs), tab_area);

    match app.bottom_tab {
        BottomTab::Timeline => {
            if let Some(trace) = selected_trace(state, app) {
                let visible = body_area.height as usize;
                let lines: Vec<Line> = trace
                    .events
                    .iter()
                    .rev()
                    .take(visible)
                    .rev()
                    .map(|event| {
                        Line::from(format!(
                            "t={}s  {}",
                            event.time_secs,
                            event
                                .kind
                                .describe(event.node_idx, event.ttl, event.hop_count)
                        ))
                    })
                    .collect();
                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), body_area);
            } else {
                frame.render_widget(Paragraph::new("No selected trace."), body_area);
            }
        }
        BottomTab::Graph => {
            if let Some(trace) = selected_trace(state, app) {
                let labels = trace_path_descriptions(trace);
                let path = if labels.is_empty() {
                    trace.from_idx.to_string()
                } else {
                    labels.join(" -> ")
                };
                let lines = vec![
                    Line::styled(
                        "Selected trace path",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::from(format!(
                        "src={}  dst={}  status={}",
                        trace.from_idx,
                        trace.to_idx,
                        trace.terminal_status.as_str()
                    )),
                    Line::from(path),
                ];
                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), body_area);
            } else {
                frame.render_widget(Paragraph::new("No selected trace."), body_area);
            }
        }
        BottomTab::Packet => {
            if let Some(trace) = selected_trace(state, app) {
                let latest = trace.events.last();
                let lines = vec![
                    Line::styled(
                        "Packet view",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::from(format!(
                        "type=0x{:02x}  flags=0b{:08b}",
                        trace.packet_type, trace.packet_flags
                    )),
                    Line::from(format!("msg_id={:02x?}", trace.message_id)),
                    Line::from(format!(
                        "src=node {}  dst={}",
                        trace.from_idx,
                        if trace.is_broadcast {
                            "broadcast".to_string()
                        } else {
                            format!("node {}", trace.to_idx)
                        }
                    )),
                    Line::from(format!("dst_addr={:02x?}", trace.dst_addr)),
                    Line::from(format!(
                        "ttl_start={}  latest_ttl={}  latest_hop={}",
                        trace.ttl_at_send,
                        latest.map(|e| e.ttl).unwrap_or(trace.ttl_at_send),
                        latest.map(|e| e.hop_count).unwrap_or(0)
                    )),
                    Line::from(format!(
                        "mode={}  status={}",
                        if trace.is_broadcast {
                            "broadcast"
                        } else {
                            "directed"
                        },
                        trace.terminal_status.as_str()
                    )),
                ];
                frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), body_area);
            } else {
                frame.render_widget(Paragraph::new("No selected trace."), body_area);
            }
        }
        BottomTab::Logs => {
            let visible = body_area.height as usize;
            let logs = crate::tui_logger::get_logs(visible);
            let lines: Vec<Line> = logs
                .iter()
                .map(|s| {
                    let style = if s.starts_with("[ERROR") {
                        Style::default().fg(Color::Red)
                    } else if s.starts_with("[WARN") {
                        Style::default().fg(Color::Yellow)
                    } else if s.starts_with("[DEBUG") || s.starts_with("[TRACE") {
                        Style::default().fg(Color::DarkGray)
                    } else {
                        Style::default()
                    };
                    Line::styled(s.as_str(), style)
                })
                .collect();
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), body_area);
        }
    }

    frame.render_widget(
        Paragraph::new(
            " [↑↓] Select   [N] Modes   [F] Filter   [M] Send   [R] Scenario   [G] Tabs   [H] Help",
        )
        .style(Style::default().fg(Color::DarkGray)),
        hint_area,
    );
}

fn render_input_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let prompt = match app.input_target {
        InputTarget::DropProb { from, to } => format!("Drop % for {} → {}: ", from, to),
        InputTarget::MessageFrom => "Message from node #: ".to_string(),
        InputTarget::MessageTo => "Message to node # (or * / all): ".to_string(),
        InputTarget::MessageBody {
            from,
            to,
            is_broadcast,
        } => {
            if is_broadcast {
                format!("Broadcast from {}: ", from)
            } else {
                format!("Message {} → {}: ", from, to)
            }
        }
        InputTarget::None => "Input: ".to_string(),
    };

    let text = format!("{}{}_", prompt, app.input_buf);
    let popup_area = centered_rect(60, 12, area);
    frame.render_widget(Clear, popup_area);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Send message (Enter=confirm, Esc=cancel) "),
            )
            .style(Style::default().fg(Color::White)),
        popup_area,
    );
}

fn render_scenario_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let presets = scenario::presets();
    let selected = presets
        .get(app.selected_scenario)
        .copied()
        .unwrap_or_else(|| presets[0]);

    let popup_area = centered_rect(80, 60, area);
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Scenarios (Enter=apply, Esc=cancel) ");
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let sections = Layout::vertical([Constraint::Length(6), Constraint::Fill(1)]).split(inner);

    let details = vec![
        Line::styled(
            selected.name,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(selected.description),
        Line::styled(
            format!("Expect: {}", selected.expected_outcome),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    frame.render_widget(
        Paragraph::new(details).wrap(Wrap { trim: false }),
        sections[0],
    );

    let items: Vec<ListItem> = presets
        .iter()
        .enumerate()
        .map(|(idx, preset)| {
            let mut style = Style::default();
            if idx == app.selected_scenario {
                style = style.add_modifier(Modifier::REVERSED);
            }
            if app.current_scenario == Some(preset.id) {
                style = style.fg(Color::Green);
            }
            ListItem::new(format!(" {} — {}", preset.name, preset.description)).style(style)
        })
        .collect();
    frame.render_widget(List::new(items), sections[1]);
}

fn render_help_overlay(frame: &mut Frame, area: Rect) {
    let popup_area = centered_rect(72, 60, area);
    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help (Esc=close) ");
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let lines = vec![
        Line::styled(
            "What this UI is for",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(
            "Follow one selected message trace hop by hop through routing-core-backed forwarding.",
        ),
        Line::from("Switch to Nodes mode to edit node capabilities and behavior flags."),
        Line::raw(""),
        Line::styled(
            "Keys",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from("  ↑↓  select trace or node"),
        Line::from("  N   switch Trace / Nodes mode"),
        Line::from("  M   compose/send manual message"),
        Line::from("  R   switch scenario"),
        Line::from("  G   timeline/logs"),
        Line::from("  H   toggle help"),
        Line::from("  Q   quit"),
        Line::raw(""),
        Line::styled(
            "Node edit keys",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from("  [1]-[6] toggle route/store/app/bridge/low-energy/mobile"),
        Line::from("  [A][C][I][O][E] toggle advertise/scan/initiate/respond/emit_sensor"),
        Line::from("  [T] cycle type   [Z] activate next node   [X] deactivate selected tail node"),
        Line::raw(""),
        Line::styled(
            "Capability codes",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from("  L low-energy   R route   A application   B bridge   M mobile"),
    ];

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn selected_trace<'a>(state: &'a TuiState, app: &App) -> Option<&'a MessageTrace> {
    let filtered = state.filtered_trace_indices(app.trace_filter);
    filtered
        .get(app.selected_trace)
        .and_then(|idx| state.traces.get(*idx))
}

fn trace_hop_edges(trace: &MessageTrace) -> Vec<(usize, usize)> {
    trace
        .events
        .iter()
        .filter_map(|event| match event.kind {
            TraceEventKind::Forwarded { to_node } => Some((event.node_idx, to_node)),
            _ => None,
        })
        .collect()
}

fn trace_path_nodes(trace: &MessageTrace) -> Vec<usize> {
    let mut nodes = vec![trace.from_idx];
    for (_, to_node) in trace_hop_edges(trace) {
        if nodes.last().copied() != Some(to_node) {
            nodes.push(to_node);
        }
    }
    if trace.is_broadcast {
        let mut broadcast_seen = trace
            .events
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::ObservedBroadcast))
            .map(|event| event.node_idx)
            .collect::<Vec<_>>();
        broadcast_seen.sort_unstable();
        broadcast_seen.dedup();
        for node in broadcast_seen {
            if !nodes.contains(&node) {
                nodes.push(node);
            }
        }
    } else if trace
        .events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::Delivered))
        && trace.to_idx < MAX_NODES
        && nodes.last().copied() != Some(trace.to_idx)
    {
        nodes.push(trace.to_idx);
    }
    nodes
}

fn trace_path_descriptions(trace: &MessageTrace) -> Vec<String> {
    let mut labels = vec![format!("{}(src)", trace.from_idx)];
    for event in trace.events.iter() {
        match event.kind {
            TraceEventKind::Forwarded { to_node } => {
                labels.push(format!("{}(h{},t{})", to_node, event.hop_count, event.ttl));
            }
            TraceEventKind::Delivered if !trace.is_broadcast && trace.to_idx < MAX_NODES => {
                if labels
                    .last()
                    .map(|s| s.starts_with(&trace.to_idx.to_string()))
                    .unwrap_or(false)
                {
                    continue;
                }
                labels.push(format!("{}(dst)", trace.to_idx));
            }
            _ => {}
        }
    }
    if trace.is_broadcast {
        let mut seen = trace
            .events
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::ObservedBroadcast))
            .map(|event| event.node_idx)
            .collect::<Vec<_>>();
        seen.sort_unstable();
        seen.dedup();
        if !seen.is_empty() {
            labels.push(format!("seen={:?}", seen));
        }
    }
    labels
}

fn node_positions(n_active: usize, width: u16, height: u16) -> Vec<(usize, usize)> {
    if n_active == 0 {
        return vec![];
    }

    let cols = ((n_active as f32).sqrt().ceil() as usize).max(2);
    let rows = n_active.div_ceil(cols);
    let x_step = (width as usize).saturating_sub(4).max(1) / cols.max(1);
    let y_step = (height as usize).saturating_sub(3).max(1) / rows.max(1);

    (0..n_active)
        .map(|idx| {
            let col = idx % cols;
            let row = idx / cols;
            let x = 1 + col * x_step;
            let y = 1 + row * y_step;
            (
                x.min(width.saturating_sub(4) as usize),
                y.min(height.saturating_sub(2) as usize),
            )
        })
        .collect()
}

fn draw_link(
    canvas: &mut [Vec<char>],
    styles: &mut [Vec<Style>],
    from: (usize, usize),
    to: (usize, usize),
    style: Style,
) {
    let (mut x0, mut y0) = (from.0 as isize, from.1 as isize);
    let (x1, y1) = (to.0 as isize, to.1 as isize);
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;

    loop {
        if x0 >= 0
            && y0 >= 0
            && (y0 as usize) < canvas.len()
            && (x0 as usize) < canvas[y0 as usize].len()
            && canvas[y0 as usize][x0 as usize] == ' '
        {
            canvas[y0 as usize][x0 as usize] = if dx > -dy { '─' } else { '│' };
            styles[y0 as usize][x0 as usize] = style;
        }
        if x0 == x1 && y0 == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x0 += sx;
        }
        if e2 <= dx {
            err += dx;
            y0 += sy;
        }
    }
}

fn put_str(
    canvas: &mut [Vec<char>],
    styles: &mut [Vec<Style>],
    x: usize,
    y: usize,
    text: &str,
    style: Style,
) {
    if y >= canvas.len() {
        return;
    }
    for (offset, ch) in text.chars().enumerate() {
        let px = x + offset;
        if px >= canvas[y].len() {
            break;
        }
        canvas[y][px] = ch;
        styles[y][px] = style;
    }
}

fn selected_link_pair(app: &App, config: &SimConfig) -> Option<(usize, usize)> {
    if app.selected_link_node >= config.n_active {
        return None;
    }
    let mut row = 0usize;
    for peer in 0..config.n_active {
        if peer == app.selected_link_node {
            continue;
        }
        if row == app.selected_link_peer_row {
            return Some((app.selected_link_node, peer));
        }
        row += 1;
    }
    None
}

fn capability_short(bits: u16) -> String {
    let mut s = String::new();
    if bits & Capabilities::LOW_ENERGY != 0 {
        s.push('L');
    }
    if bits & Capabilities::ROUTE != 0 {
        s.push('R');
    }
    if bits & Capabilities::APPLICATION != 0 {
        s.push('A');
    }
    if bits & Capabilities::BRIDGE != 0 {
        s.push('B');
    }
    if bits & Capabilities::MOBILE != 0 {
        s.push('M');
    }
    if s.is_empty() {
        s.push('-');
    }
    s
}

fn capability_long(bits: u16) -> String {
    let mut labels = vec![];
    if bits & Capabilities::LOW_ENERGY != 0 {
        labels.push("low-energy");
    }
    if bits & Capabilities::ROUTE != 0 {
        labels.push("route");
    }
    if bits & Capabilities::STORE != 0 {
        labels.push("store");
    }
    if bits & Capabilities::APPLICATION != 0 {
        labels.push("app");
    }
    if bits & Capabilities::BRIDGE != 0 {
        labels.push("bridge");
    }
    if bits & Capabilities::MOBILE != 0 {
        labels.push("mobile");
    }
    if labels.is_empty() {
        "none".to_string()
    } else {
        labels.join("|")
    }
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}
