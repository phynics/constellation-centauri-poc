//! Trace-centric ratatui rendering.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

use routing_core::node::roles::Capabilities;

use super::app::{App, BottomTab, InputTarget, Mode};
use crate::scenario;
use crate::sim_state::{MessageTrace, SimConfig, TuiState, MAX_NODES};

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
    render_trace_list(frame, app, state, top[0]);
    render_trace_detail(frame, app, state, top[1]);
    render_trace_context(frame, app, state, config, top[2]);
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
            delivery_status(trace)
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
                " traces={}  active={}  {}  [M] send  [R] scenario  [H] help",
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

    let visible = inner.height as usize;
    let total = state.traces.len();
    let start = total.saturating_sub(visible).min(app.selected_trace);

    let items: Vec<ListItem> = state
        .traces
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(idx, trace)| {
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
                delivery_status(trace),
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
            "Delivered: {}",
            trace
                .delivered_secs
                .map(|secs| format!("t={}s", secs))
                .unwrap_or_else(|| "pending".to_string())
        )),
        Line::from(format!("Delivery model: direct sim inbox delivery")),
    ];

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
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
    let dst_node = &state.nodes[trace.to_idx.min(MAX_NODES - 1)];
    let current_link = config.link_enabled[trace.from_idx][trace.to_idx];
    let current_drop = config.drop_prob[trace.from_idx][trace.to_idx];
    let dst_peer = src_node
        .peers
        .iter()
        .find(|peer| peer.short_addr == dst_node.short_addr);
    let dst_visible_from_src = dst_peer
        .map(|peer| {
            if peer.hop_count == 0 {
                "direct"
            } else {
                "indirect"
            }
        })
        .unwrap_or("not seen");
    let dst_trust = dst_peer
        .map(|peer| peer.trust.to_string())
        .unwrap_or_else(|| "n/a".to_string());

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
        Line::from(format!("Dst uptime now: {}s", dst_node.uptime_secs)),
        Line::from(format!(
            "Src caps now: {}",
            capability_long(src_node.capabilities)
        )),
        Line::from(format!(
            "Dst caps now: {}",
            capability_long(dst_node.capabilities)
        )),
        Line::from(format!("Src peers now: {}", src_node.peers.len())),
        Line::from(format!("Dst peers now: {}", dst_node.peers.len())),
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

    let (timeline_style, logs_style) = match app.bottom_tab {
        BottomTab::Timeline => (tab_style_active, tab_style_inactive),
        BottomTab::Logs => (tab_style_inactive, tab_style_active),
    };

    let tabs = Line::from(vec![
        Span::raw(" "),
        Span::styled(" Timeline ", timeline_style),
        Span::raw("  "),
        Span::styled(" Logs ", logs_style),
        Span::styled("   [G] switch", Style::default().fg(Color::DarkGray)),
    ]);
    frame.render_widget(Paragraph::new(tabs), tab_area);

    match app.bottom_tab {
        BottomTab::Timeline => {
            if let Some(trace) = selected_trace(state, app) {
                let delivered = trace
                    .delivered_secs
                    .map(|secs| {
                        format!(
                            "t={}s: destination {} consumed inbox item",
                            secs, trace.to_idx
                        )
                    })
                    .unwrap_or_else(|| {
                        "pending: destination has not consumed the inbox item yet".to_string()
                    });
                let lines = vec![
                    Line::from(format!(
                        "t={}s: trace #{} created at source node {}",
                        trace.created_secs, trace.id, trace.from_idx
                    )),
                    Line::from(format!(
                        "t={}s: direct enqueue to destination inbox {}",
                        trace.created_secs, trace.to_idx
                    )),
                    Line::from(delivered),
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
            " [↑↓] Select trace   [M] Send message   [R] Scenario   [H] Help   [Q] Quit",
        )
        .style(Style::default().fg(Color::DarkGray)),
        hint_area,
    );
}

fn render_input_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let prompt = match app.input_target {
        InputTarget::MessageFrom => "Message from node #: ".to_string(),
        InputTarget::MessageTo => "Message to node #: ".to_string(),
        InputTarget::MessageBody { from, to } => format!("Message {} → {}: ", from, to),
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
        Line::from("Follow one selected message trace from creation to delivery."),
        Line::from("This pass uses the simulator's current direct inbox delivery model."),
        Line::raw(""),
        Line::styled(
            "Keys",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from("  ↑↓  select trace"),
        Line::from("  M   compose/send manual message"),
        Line::from("  R   switch scenario"),
        Line::from("  G   timeline/logs"),
        Line::from("  H   toggle help"),
        Line::from("  Q   quit"),
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
    state.traces.get(app.selected_trace)
}

fn delivery_status(trace: &MessageTrace) -> &'static str {
    if trace.delivered_secs.is_some() {
        "delivered"
    } else {
        "pending"
    }
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
