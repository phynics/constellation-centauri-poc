//! Companion TUI application state.
//!
//! Purpose: hold interactive UI state and key handling for the companion's
//! terminal interface.
//!
//! Design decisions:
//! - Keep presentation state and UI actions in the TUI layer, separate from BLE
//!   runtime and shared protocol logic.
use crossterm::event::{KeyCode, KeyEvent};

pub enum UiAction {
    None,
    Quit,
    EnrollSelected,
    ResetNetworkKey,
    PingSelected,
    SendMessage { body: String },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Peers,
    Network,
    Local,
    Events,
}

pub struct App {
    pub view: ViewMode,
    pub selected_peer: usize,
    pub composing_message: bool,
    pub message_input: String,
}

impl App {
    pub fn new() -> Self {
        Self {
            view: ViewMode::Peers,
            selected_peer: 0,
            composing_message: false,
            message_input: String::new(),
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, peer_count: usize) -> UiAction {
        if self.composing_message {
            match key.code {
                KeyCode::Esc => {
                    self.composing_message = false;
                    self.message_input.clear();
                }
                KeyCode::Enter => {
                    let body = self.message_input.trim().to_string();
                    self.composing_message = false;
                    self.message_input.clear();
                    if !body.is_empty() {
                        return UiAction::SendMessage { body };
                    }
                }
                KeyCode::Backspace => {
                    self.message_input.pop();
                }
                KeyCode::Char(ch) => {
                    if self.message_input.len() < 160 {
                        self.message_input.push(ch);
                    }
                }
                _ => {}
            }
            return UiAction::None;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return UiAction::Quit,
            KeyCode::Char('n') | KeyCode::Tab => {
                self.view = match self.view {
                    ViewMode::Peers => ViewMode::Local,
                    ViewMode::Local => ViewMode::Network,
                    ViewMode::Network => ViewMode::Events,
                    ViewMode::Events => ViewMode::Peers,
                };
            }
            KeyCode::Char('e') | KeyCode::Char('E') if self.view == ViewMode::Peers => {
                return UiAction::EnrollSelected;
            }
            KeyCode::Char('r') | KeyCode::Char('R') if self.view == ViewMode::Local => {
                return UiAction::ResetNetworkKey;
            }
            KeyCode::Char('m') | KeyCode::Char('M') if self.view == ViewMode::Network => {
                if peer_count > 0 {
                    self.composing_message = true;
                }
            }
            KeyCode::Char('p') | KeyCode::Char('P') if self.view == ViewMode::Network => {
                if peer_count > 0 {
                    return UiAction::PingSelected;
                }
            }
            KeyCode::Up => {
                self.selected_peer = self.selected_peer.saturating_sub(1);
            }
            KeyCode::Down => {
                if self.selected_peer + 1 < peer_count {
                    self.selected_peer += 1;
                }
            }
            _ => {}
        }
        UiAction::None
    }
}
