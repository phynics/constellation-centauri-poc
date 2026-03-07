//! Ratatui rendering.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Row, Table, Wrap},
};

use crate::sim_state::{SimConfig, TuiState, MAX_NODES};
use super::app::{App, BottomTab, InputTarget, Mode, Panel};

pub fn render(frame: &mut Frame, app: &App, state: &TuiState, config: &SimConfig) {
    let area = frame.area();

    // Vertical: top section + message log (12 rows).
    let vert = Layout::vertical([Constraint::Fill(1), Constraint::Length(12)]).split(area);
    // Horizontal: node list (24 cols) + detail pane.
    let horiz = Layout::horizontal([Constraint::Length(24), Constraint::Fill(1)]).split(vert[0]);

    render_node_list(frame, app, state, config, horiz[0]);
    render_node_detail(frame, app, state, config, horiz[1]);
    render_message_log(frame, app, state, config, vert[1]);

    if app.mode != Mode::Normal {
        render_input_overlay(frame, app, area);
    }
}

// ── Node list ─────────────────────────────────────────────────────────────────

fn render_node_list(
    frame: &mut Frame,
    app: &App,
    state: &TuiState,
    config: &SimConfig,
    area: Rect,
) {
    let focused = app.focus == Panel::NodeList;
    let border_style = focus_style(focused);

    let items: Vec<ListItem> = (0..MAX_NODES)
        .map(|i| {
            let is_selected = i == app.selected_node;

            if i >= config.n_active {
                let label = format!(" ○ {}  [inactive]", i);
                let mut style = Style::default().fg(Color::DarkGray);
                if is_selected && focused {
                    style = style.add_modifier(Modifier::REVERSED);
                }
                return ListItem::new(label).style(style);
            }

            let node = &state.nodes[i];
            let addr = format!("{:02x}{:02x}", node.short_addr[0], node.short_addr[1]);
            let type_str = config.node_types[i].as_str();
            let label = format!(" ● {}  {}  {}  {}p", i, addr, type_str, node.peers.len());

            let mut style = Style::default().fg(Color::Green);
            if is_selected && focused {
                style = style.add_modifier(Modifier::REVERSED);
            } else if is_selected {
                style = style.add_modifier(Modifier::BOLD);
            }
            ListItem::new(label).style(style)
        })
        .collect();

    let block = Block::default()
        .title(" Nodes (↑↓) ")
        .borders(Borders::ALL)
        .border_style(border_style);

    // Split area: list items + hint line at bottom.
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let list_h = inner.height.saturating_sub(1);
    let list_area = Rect { height: list_h, ..inner };
    let hint_area = Rect { y: inner.y + list_h, height: 1, ..inner };

    frame.render_widget(List::new(items), list_area);

    let hint = Paragraph::new(Line::from(vec![
        Span::raw(" ["),
        Span::styled("A", Style::default().fg(Color::Cyan)),
        Span::raw("]dd  ["),
        Span::styled("D", Style::default().fg(Color::Cyan)),
        Span::raw("]el"),
    ]))
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(hint, hint_area);
}

// ── Node detail / link config ─────────────────────────────────────────────────

fn render_node_detail(
    frame: &mut Frame,
    app: &App,
    state: &TuiState,
    config: &SimConfig,
    area: Rect,
) {
    let focused = app.focus == Panel::NodeDetail;
    let node_idx = app.selected_node;
    let node = &state.nodes[node_idx];

    let title = format!(
        " Node {}: {:02x}{:02x} ",
        node_idx, node.short_addr[0], node.short_addr[1]
    );

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(focus_style(focused));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if node_idx >= config.n_active {
        frame.render_widget(
            Paragraph::new(" [inactive node]").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    // Header: type / uptime / peer count.
    let header_area = Rect { height: 2, ..inner };
    let links_area = Rect {
        y: inner.y + 2,
        height: inner.height.saturating_sub(4),
        ..inner
    };
    let hints_area = Rect {
        y: inner.y + inner.height.saturating_sub(2),
        height: 1,
        ..inner
    };

    frame.render_widget(
        Paragraph::new(format!(
            " Type: [{}]   Uptime: {}s   Peers: {}",
            config.node_types[node_idx].as_str(),
            node.uptime_secs,
            node.peers.len()
        )),
        header_area,
    );

    // Links table — one row per peer (excluding self).
    let rows: Vec<Row> = (0..MAX_NODES)
        .filter(|&i| i != node_idx)
        .enumerate()
        .map(|(row_idx, i)| {
            let is_sel = focused && row_idx == app.selected_link;
            let sel_style = if is_sel {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };

            if i >= config.n_active {
                return Row::new(vec![
                    "✗".to_string(),
                    i.to_string(),
                    "[inactive]".to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                    "[L]".to_string(),
                ])
                .style(sel_style.fg(Color::DarkGray));
            }

            let enabled = config.link_enabled[node_idx][i];
            let drop = config.drop_prob[node_idx][i];

            let peer_snap =
                node.peers.iter().find(|p| p.short_addr == state.nodes[i].short_addr);

            let (status, trust_str, hop_str) = if !enabled {
                ("✗", String::new(), String::new())
            } else if let Some(p) = peer_snap {
                let s = if p.hop_count == 0 { "✓" } else { "~" };
                (s, format!("trust={}", p.trust), format!("hop={}", p.hop_count))
            } else {
                ("?", String::new(), String::new())
            };

            let addr = format!("{:02x}{:02x}", state.nodes[i].short_addr[0], state.nodes[i].short_addr[1]);
            let drop_str = format!("drop={:3}%", drop);
            let hints = if enabled { "[L][P]" } else { "[L]" };

            Row::new(vec![
                status.to_string(),
                i.to_string(),
                addr,
                trust_str,
                hop_str,
                drop_str,
                hints.to_string(),
            ])
            .style(sel_style)
        })
        .collect();

    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Length(3),
                Constraint::Length(6),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Length(9),
                Constraint::Length(8),
            ],
        ),
        links_area,
    );

    frame.render_widget(
        Paragraph::new(
            " [T] Cycle type   [L] Toggle link   [P] Set drop %",
        )
        .style(Style::default().fg(Color::DarkGray)),
        hints_area,
    );
}

// ── Bottom panel: Messages / Logs tabs ────────────────────────────────────────

fn render_message_log(
    frame: &mut Frame,
    app: &App,
    state: &TuiState,
    config: &SimConfig,
    area: Rect,
) {
    let focused = app.focus == Panel::MessageLog;

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_style(focused));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Layout: tab-header row | content | hint row
    let tab_area  = Rect { height: 1, ..inner };
    let hint_area = Rect { y: inner.y + inner.height.saturating_sub(1), height: 1, ..inner };
    let body_area = Rect {
        y: inner.y + 1,
        height: inner.height.saturating_sub(2),
        ..inner
    };

    // ── Tab headers ──────────────────────────────────────────────────────────
    let active_style   = Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD);
    let inactive_style = Style::default().fg(Color::DarkGray);

    let (msg_style, log_style) = match app.bottom_tab {
        BottomTab::Messages => (active_style, inactive_style),
        BottomTab::Logs     => (inactive_style, active_style),
    };

    let tab_line = Line::from(vec![
        Span::raw(" "),
        Span::styled(" Messages ", msg_style),
        Span::raw("  "),
        Span::styled(" Logs ", log_style),
        Span::styled("   [G] switch tab", Style::default().fg(Color::DarkGray)),
    ]);
    frame.render_widget(Paragraph::new(tab_line), tab_area);

    // ── Body ─────────────────────────────────────────────────────────────────
    match app.bottom_tab {
        BottomTab::Messages => {
            let visible = body_area.height as usize;
            let lines: Vec<Line> = state
                .messages
                .iter()
                .rev()
                .take(visible)
                .rev()
                .map(|m| {
                    let to = if m.to_idx >= MAX_NODES {
                        "all".to_string()
                    } else {
                        m.to_idx.to_string()
                    };
                    Line::from(format!(
                        "  t={:3}s  {} → {}  [{:7}]  {}",
                        m.time_secs, m.from_idx, to, m.kind.as_str(), m.body
                    ))
                })
                .collect();
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), body_area);
        }

        BottomTab::Logs => {
            let visible = body_area.height as usize;
            let logs = crate::tui_logger::get_logs(visible);
            let lines: Vec<Line> = logs
                .iter()
                .map(|s| {
                    // Colour by level prefix.
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

    // ── Hint row ─────────────────────────────────────────────────────────────
    let sensor_status = if config.sensor_auto {
        format!("ON, {}s", config.sensor_interval_secs)
    } else {
        "OFF".to_string()
    };
    frame.render_widget(
        Paragraph::new(format!(
            " [M] Manual msg   [S] Sensor auto ({})   [Tab] Switch panel",
            sensor_status
        ))
        .style(Style::default().fg(Color::DarkGray)),
        hint_area,
    );
}

// ── Input overlay ─────────────────────────────────────────────────────────────

fn render_input_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let prompt = match app.input_target {
        InputTarget::DropProb { node, link } => {
            format!("Drop % for node {} → {}: ", node, link)
        }
        InputTarget::MessageFrom => "Message from node #: ".to_string(),
        InputTarget::MessageTo => "Message to node #: ".to_string(),
        InputTarget::MessageBody { from, to } => format!("Message {} → {}: ", from, to),
        InputTarget::None => "Input: ".to_string(),
    };

    let text = format!("{}{}_", prompt, app.input_buf);

    let w = (text.len() as u16 + 4).min(area.width.saturating_sub(4)).max(40);
    let h = 3u16;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let popup_area = Rect { x, y, width: w, height: h };

    frame.render_widget(Clear, popup_area);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Input (Enter=confirm, Esc=cancel) "),
            )
            .style(Style::default().fg(Color::White)),
        popup_area,
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn focus_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
}
