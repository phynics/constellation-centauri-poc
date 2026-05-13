use crossterm::event::{KeyCode, KeyEvent};

pub enum UiAction {
    None,
    Quit,
    EnrollSelected,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Peers,
    Local,
    Events,
}

pub struct App {
    pub view: ViewMode,
    pub selected_peer: usize,
}

impl App {
    pub fn new() -> Self {
        Self {
            view: ViewMode::Peers,
            selected_peer: 0,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, peer_count: usize) -> UiAction {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return UiAction::Quit,
            KeyCode::Char('n') | KeyCode::Tab => {
                self.view = match self.view {
                    ViewMode::Peers => ViewMode::Local,
                    ViewMode::Local => ViewMode::Events,
                    ViewMode::Events => ViewMode::Peers,
                };
            }
            KeyCode::Char('e') | KeyCode::Char('E') if self.view == ViewMode::Peers => {
                return UiAction::EnrollSelected;
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
