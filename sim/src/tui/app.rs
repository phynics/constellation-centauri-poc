//! TUI application state and keyboard event handling.

use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;

use crossterm::event::{KeyCode, KeyEvent};

use crate::sim_state::{MessageKind, SimCommand, SimConfig, MAX_NODES};

#[derive(Clone, Copy, PartialEq)]
pub enum Panel {
    NodeList,
    NodeDetail,
    MessageLog,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Normal,
    InputDropProb,
    InputMessage,
}

#[derive(Clone, Copy, PartialEq)]
pub enum InputTarget {
    None,
    DropProb { node: usize, link: usize },
    MessageFrom,
    MessageTo,
    MessageBody { from: usize, to: usize },
}

#[derive(Clone, Copy, PartialEq)]
pub enum BottomTab {
    Messages,
    Logs,
}

pub struct App {
    pub selected_node: usize,
    pub selected_link: usize,
    pub focus: Panel,
    pub mode: Mode,
    pub input_buf: String,
    pub input_target: InputTarget,
    pub pending_msg_from: usize,
    pub pending_msg_to: usize,
    pub bottom_tab: BottomTab,
}

impl App {
    pub fn new() -> Self {
        Self {
            selected_node: 0,
            selected_link: 0,
            focus: Panel::NodeList,
            mode: Mode::Normal,
            input_buf: String::new(),
            input_target: InputTarget::None,
            pending_msg_from: 0,
            pending_msg_to: 1,
            bottom_tab: BottomTab::Messages,
        }
    }

    /// Returns `true` if the app should quit.
    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        sim_config: &Arc<Mutex<SimConfig>>,
        cmd_tx: &Sender<SimCommand>,
    ) -> bool {
        if self.mode != Mode::Normal {
            return self.handle_input_key(key, sim_config, cmd_tx);
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,

            KeyCode::Tab => {
                self.focus = match self.focus {
                    Panel::NodeList => Panel::NodeDetail,
                    Panel::NodeDetail => Panel::MessageLog,
                    Panel::MessageLog => Panel::NodeList,
                };
            }

            KeyCode::Up => match self.focus {
                Panel::NodeList => {
                    if self.selected_node > 0 {
                        self.selected_node -= 1;
                        self.selected_link = 0;
                    }
                }
                Panel::NodeDetail => {
                    if self.selected_link > 0 {
                        self.selected_link -= 1;
                    }
                }
                _ => {}
            },

            KeyCode::Down => match self.focus {
                Panel::NodeList => {
                    if self.selected_node + 1 < MAX_NODES {
                        self.selected_node += 1;
                        self.selected_link = 0;
                    }
                }
                Panel::NodeDetail => {
                    // Bounds are checked in ui.rs — allow free increment.
                    if self.selected_link + 2 < MAX_NODES {
                        self.selected_link += 1;
                    }
                }
                _ => {}
            },

            KeyCode::Char('l') | KeyCode::Char('L') => {
                if self.focus == Panel::NodeDetail {
                    let from = self.selected_node;
                    // link row index maps to peer index (skip self).
                    let to = link_row_to_peer(from, self.selected_link);
                    if let Some(to) = to {
                        let mut cfg = sim_config.lock().unwrap();
                        cfg.link_enabled[from][to] = !cfg.link_enabled[from][to];
                    }
                }
            }

            KeyCode::Char('p') | KeyCode::Char('P') => {
                if self.focus == Panel::NodeDetail {
                    let from = self.selected_node;
                    let to = link_row_to_peer(from, self.selected_link);
                    if let Some(to) = to {
                        self.mode = Mode::InputDropProb;
                        self.input_buf.clear();
                        self.input_target = InputTarget::DropProb { node: from, link: to };
                    }
                }
            }

            KeyCode::Char('t') | KeyCode::Char('T') => {
                if self.focus == Panel::NodeList || self.focus == Panel::NodeDetail {
                    let node = self.selected_node;
                    let mut cfg = sim_config.lock().unwrap();
                    cfg.node_types[node] = cfg.node_types[node].cycle();
                }
            }

            KeyCode::Char('a') | KeyCode::Char('A') => {
                if self.focus == Panel::NodeList {
                    let _ = cmd_tx.send(SimCommand::AddNode);
                }
            }

            KeyCode::Char('d') | KeyCode::Char('D') => {
                if self.focus == Panel::NodeList {
                    let _ = cmd_tx.send(SimCommand::RemoveNode(self.selected_node));
                }
            }

            KeyCode::Char('m') | KeyCode::Char('M') => {
                if self.focus == Panel::MessageLog {
                    self.mode = Mode::InputMessage;
                    self.input_buf.clear();
                    self.input_target = InputTarget::MessageFrom;
                }
            }

            KeyCode::Char('s') | KeyCode::Char('S') => {
                if self.focus == Panel::MessageLog {
                    let mut cfg = sim_config.lock().unwrap();
                    cfg.sensor_auto = !cfg.sensor_auto;
                }
            }

            // Switch bottom-panel tab: Messages ↔ Logs (works from any panel).
            KeyCode::Char('g') | KeyCode::Char('G') => {
                self.bottom_tab = match self.bottom_tab {
                    BottomTab::Messages => BottomTab::Logs,
                    BottomTab::Logs => BottomTab::Messages,
                };
            }

            _ => {}
        }

        false
    }

    fn handle_input_key(
        &mut self,
        key: KeyEvent,
        sim_config: &Arc<Mutex<SimConfig>>,
        cmd_tx: &Sender<SimCommand>,
    ) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.input_target = InputTarget::None;
                self.input_buf.clear();
            }

            KeyCode::Enter => {
                match self.input_target {
                    InputTarget::DropProb { node, link } => {
                        if let Ok(prob) = self.input_buf.trim().parse::<u8>() {
                            let prob = prob.min(100);
                            sim_config.lock().unwrap().drop_prob[node][link] = prob;
                        }
                        self.mode = Mode::Normal;
                        self.input_target = InputTarget::None;
                        self.input_buf.clear();
                    }

                    InputTarget::MessageFrom => {
                        if let Ok(from) = self.input_buf.trim().parse::<usize>() {
                            if from < MAX_NODES {
                                self.pending_msg_from = from;
                                self.input_target = InputTarget::MessageTo;
                                self.input_buf.clear();
                            }
                        }
                    }

                    InputTarget::MessageTo => {
                        if let Ok(to) = self.input_buf.trim().parse::<usize>() {
                            if to < MAX_NODES {
                                self.pending_msg_to = to;
                                self.input_target = InputTarget::MessageBody {
                                    from: self.pending_msg_from,
                                    to,
                                };
                                self.input_buf.clear();
                            }
                        }
                    }

                    InputTarget::MessageBody { from, to } => {
                        let _ = cmd_tx.send(SimCommand::SendMessage {
                            from,
                            to,
                            kind: MessageKind::Manual,
                            body: self.input_buf.clone(),
                        });
                        self.mode = Mode::Normal;
                        self.input_target = InputTarget::None;
                        self.input_buf.clear();
                    }

                    InputTarget::None => {
                        self.mode = Mode::Normal;
                    }
                }
            }

            KeyCode::Backspace => {
                self.input_buf.pop();
            }

            KeyCode::Char(c) => {
                self.input_buf.push(c);
            }

            _ => {}
        }

        false
    }
}

/// Convert a zero-based link-row index into a peer node index,
/// skipping `node_idx` itself.
pub fn link_row_to_peer(node_idx: usize, row: usize) -> Option<usize> {
    let mut r = 0usize;
    for i in 0..MAX_NODES {
        if i == node_idx {
            continue;
        }
        if r == row {
            return Some(i);
        }
        r += 1;
    }
    None
}
