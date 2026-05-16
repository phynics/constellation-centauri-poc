//! Companion ratatui rendering.
//!
//! Purpose: render the companion diagnostics and operator UI from shared host
//! state.
//!
//! Design decisions:
//! - Keep rendering separate from event handling and BLE/runtime mutation so
//!   the UI remains a thin presentation layer.
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use super::app::{App, ViewMode};
use crate::diagnostics::state::{capability_summary, SharedState};

pub fn render(frame: &mut Frame, app: &App, state: &SharedState) {
    let area = frame.area();
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(10),
    ])
    .split(area);

    render_summary(frame, app, state, chunks[0]);
    match app.view {
        ViewMode::Peers => render_peers(frame, app, state, chunks[1]),
        ViewMode::Network => render_network(frame, app, state, chunks[1]),
        ViewMode::Local => render_local(frame, state, chunks[1]),
        ViewMode::Events => render_events(frame, state, chunks[1]),
    }
    render_footer(frame, app, state, chunks[2]);
    if app.composing_message {
        render_compose_modal(frame, app);
    }
}

fn render_summary(frame: &mut Frame, app: &App, state: &SharedState, area: ratatui::layout::Rect) {
    let title = match app.view {
        ViewMode::Peers => "Peers",
        ViewMode::Network => "Network",
        ViewMode::Local => "Local",
        ViewMode::Events => "Events",
    };
    let block = Block::default()
        .title(" Constellation Companion ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let text = vec![Line::from(vec![
        Span::styled(
            format!("view={title}"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  peers={}  network={}  scanning={}  advertising={}  [N]/Tab cycle  [Q] quit",
            state.peers.len(),
            state.routing_peers.len(),
            state.scanning,
            state.advertising
        )),
    ])];
    frame.render_widget(Paragraph::new(text), inner);
}

fn render_peers(frame: &mut Frame, app: &App, state: &SharedState, area: ratatui::layout::Rect) {
    let block = Block::default()
        .title(" Discovered peers ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if state.peers.is_empty() {
        frame.render_widget(
            Paragraph::new("Waiting for peers...").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }
    let items: Vec<ListItem> = state
        .peers
        .iter()
        .enumerate()
        .map(|(idx, peer)| {
            let mut flags = Vec::new();
            if peer.has_onboarding_service {
                flags.push("svc");
            }
            if peer.has_constellation_signature {
                flags.push("sig");
            }
            if peer.onboarding_ready {
                flags.push("ready");
            }
            if peer.network_pubkey_hex.is_some() {
                flags.push("network");
            }
            let caps = peer
                .capabilities
                .map(capability_summary)
                .unwrap_or_else(|| "?".to_string());
            let line = format!(
                "{} {:<18} rssi={:<4} flags={:<18} caps={}{}",
                if idx == app.selected_peer { '>' } else { ' ' },
                peer.name.clone().unwrap_or_else(|| peer.id.clone()),
                peer.rssi
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".into()),
                if flags.is_empty() {
                    "-".into()
                } else {
                    flags.join(",")
                },
                caps,
                peer.last_error
                    .as_ref()
                    .map(|e| format!(" err={e}"))
                    .unwrap_or_default(),
            );
            let style = if idx == app.selected_peer {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            ListItem::new(line).style(style)
        })
        .collect();
    frame.render_widget(List::new(items), inner);
}

fn render_network(frame: &mut Frame, app: &App, state: &SharedState, area: ratatui::layout::Rect) {
    let block = Block::default()
        .title(" Network nodes ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if state.routing_peers.is_empty() {
        frame.render_widget(
            Paragraph::new("No routing-core peers learned yet.")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let items: Vec<ListItem> = state
        .routing_peers
        .iter()
        .enumerate()
        .map(|(idx, peer)| {
            let line = format!(
                "{} {:02x?} trust={} hop={} caps={} transport_len={}",
                if idx == app.selected_peer { '>' } else { ' ' },
                &peer.short_addr[..4],
                peer.trust,
                peer.hop_count,
                capability_summary(peer.capabilities),
                peer.transport_len,
            );
            let style = if idx == app.selected_peer {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            ListItem::new(line).style(style)
        })
        .collect();
    frame.render_widget(List::new(items), inner);
}

fn render_local(frame: &mut Frame, state: &SharedState, area: ratatui::layout::Rect) {
    let block = Block::default().title(" Local node ").borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines = vec![
        Line::from(format!("Short addr: {:02x?}", &state.local.short_addr[..4])),
        Line::from(format!("Pubkey: {:02x?}", &state.local.pubkey[..8])),
        Line::from(format!(
            "Authority pubkey: {:02x?}",
            &state.local.authority_pubkey[..8]
        )),
        Line::from(format!(
            "Capabilities: {}",
            capability_summary(state.local.capabilities)
        )),
        Line::from(format!("Uptime: {}s", state.uptime_secs)),
        Line::from(format!(
            "Protocol signature: {}",
            state.local.protocol_signature
        )),
        Line::from(format!("Network marker: {}", state.local.network_marker)),
        Line::from(format!("Routing peers: {}", state.routing_peers.len())),
        Line::from(format!("Storage: {}", state.local.storage_dir)),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_events(frame: &mut Frame, state: &SharedState, area: ratatui::layout::Rect) {
    let block = Block::default().title(" Event log ").borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let items: Vec<ListItem> = state
        .events
        .iter()
        .rev()
        .take(inner.height as usize)
        .map(|event| ListItem::new(event.clone()))
        .collect();
    frame.render_widget(List::new(items), inner);
}

fn render_footer(frame: &mut Frame, app: &App, state: &SharedState, area: ratatui::layout::Rect) {
    let block = Block::default().title(" Details ").borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if app.view == ViewMode::Local {
        let lines = vec![
            Line::from("[R] regenerate local network authority"),
            Line::from("This only rotates the companion authority for future enrollments."),
        ];
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        return;
    }

    let selected = match app.view {
        ViewMode::Peers => state
            .peers
            .get(app.selected_peer.min(state.peers.len().saturating_sub(1))),
        ViewMode::Network => None,
        ViewMode::Events => None,
        ViewMode::Local => None,
    };
    if app.view == ViewMode::Network {
        let Some(peer) = state.routing_peers.get(
            app.selected_peer
                .min(state.routing_peers.len().saturating_sub(1)),
        ) else {
            frame.render_widget(Paragraph::new("No network node selected."), inner);
            return;
        };
        let lines = vec![
            Line::from(format!("Short addr: {:02x?}", &peer.short_addr[..4])),
            Line::from(format!("Trust: {}", peer.trust)),
            Line::from(format!("Hop count: {}", peer.hop_count)),
            Line::from(format!(
                "Capabilities: {}",
                capability_summary(peer.capabilities)
            )),
            Line::from(format!("Transport len: {}", peer.transport_len)),
            Line::from(format!("Last seen ticks: {}", peer.last_seen_ticks)),
            Line::from("[P] ping selected network node"),
            Line::from("[M] send message if this peer is directly reachable"),
        ];
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        return;
    }
    let Some(peer) = selected else {
        frame.render_widget(Paragraph::new("No peer selected."), inner);
        return;
    };

    let lines = vec![
        Line::from(format!("ID: {}", peer.id)),
        Line::from(format!(
            "Name: {}",
            peer.name.clone().unwrap_or_else(|| "<unnamed>".to_string())
        )),
        Line::from(format!(
            "Node pubkey: {}",
            peer.node_pubkey_hex
                .clone()
                .unwrap_or_else(|| "?".to_string())
        )),
        Line::from(format!(
            "Network pubkey: {}",
            peer.network_pubkey_hex
                .clone()
                .unwrap_or_else(|| "?".to_string())
        )),
        Line::from(format!("Ready for onboarding: {}", peer.onboarding_ready)),
        Line::from(if app.view == ViewMode::Network {
            "[P] ping  [M] send message to selected network node".to_string()
        } else {
            "[E] enroll selected onboarding peer".to_string()
        }),
    ];
    let mut lines = lines;
    if !state.routing_peers.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Routing snapshot",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
        for entry in state.routing_peers.iter().take(3) {
            lines.push(Line::from(format!(
                "{:02x?} trust={} hop={} caps={} transport_len={} seen={}",
                &entry.short_addr[..4],
                entry.trust,
                entry.hop_count,
                capability_summary(entry.capabilities),
                entry.transport_len,
                entry.last_seen_ticks,
            )));
        }
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_compose_modal(frame: &mut Frame, app: &App) {
    let area = centered_rect(80, 5, frame.area());
    let block = Block::default()
        .title(" Send message (Enter=send, Esc=cancel) ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(app.message_input.as_str()).wrap(Wrap { trim: false }),
        inner,
    );
}

fn centered_rect(
    width_pct: u16,
    height: u16,
    area: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height),
        Constraint::Fill(1),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - width_pct) / 2),
        Constraint::Percentage(width_pct),
        Constraint::Percentage((100 - width_pct) / 2),
    ])
    .split(vertical[1])[1]
}
