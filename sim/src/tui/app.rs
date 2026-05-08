//! TUI application state and keyboard event handling for the trace-centric UI.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use crossterm::event::{KeyCode, KeyEvent};

use crate::scenario::{self, ScenarioId};
use crate::sim_state::{MessageKind, SimCommand, SimConfig, TuiState, MAX_NODES};

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Normal,
    InputMessage,
    ScenarioSelect,
    Help,
}

#[derive(Clone, Copy, PartialEq)]
pub enum InputTarget {
    None,
    MessageFrom,
    MessageTo,
    MessageBody { from: usize, to: usize },
}

#[derive(Clone, Copy, PartialEq)]
pub enum BottomTab {
    Timeline,
    Logs,
}

pub struct App {
    pub mode: Mode,
    pub input_buf: String,
    pub input_target: InputTarget,
    pub pending_msg_from: usize,
    pub pending_msg_to: usize,
    pub bottom_tab: BottomTab,
    pub selected_trace: usize,
    pub selected_scenario: usize,
    pub current_scenario: Option<ScenarioId>,
}

impl App {
    pub fn new() -> Self {
        Self {
            mode: Mode::Normal,
            input_buf: String::new(),
            input_target: InputTarget::None,
            pending_msg_from: 0,
            pending_msg_to: 1,
            bottom_tab: BottomTab::Timeline,
            selected_trace: 0,
            selected_scenario: 0,
            current_scenario: Some(scenario::default_scenario()),
        }
    }

    /// Returns `true` if the app should quit.
    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        _sim_config: &Arc<Mutex<SimConfig>>,
        cmd_tx: &Sender<SimCommand>,
        tui_state: &Arc<Mutex<TuiState>>,
    ) -> bool {
        if self.mode == Mode::ScenarioSelect {
            return self.handle_scenario_key(key, cmd_tx);
        }

        if self.mode == Mode::Help {
            return self.handle_help_key(key);
        }

        if self.mode != Mode::Normal {
            return self.handle_input_key(key, cmd_tx);
        }

        let trace_count = tui_state.lock().unwrap().traces.len();

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,

            KeyCode::Up => {
                if self.selected_trace > 0 {
                    self.selected_trace -= 1;
                }
            }

            KeyCode::Down => {
                if self.selected_trace + 1 < trace_count {
                    self.selected_trace += 1;
                }
            }

            KeyCode::Char('m') | KeyCode::Char('M') => {
                self.mode = Mode::InputMessage;
                self.input_buf.clear();
                self.input_target = InputTarget::MessageFrom;
            }

            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.mode = Mode::ScenarioSelect;
                self.selected_scenario = self
                    .current_scenario
                    .and_then(|current| {
                        scenario::presets()
                            .iter()
                            .position(|preset| preset.id == current)
                    })
                    .unwrap_or(0);
            }

            KeyCode::Char('g') | KeyCode::Char('G') => {
                self.bottom_tab = match self.bottom_tab {
                    BottomTab::Timeline => BottomTab::Logs,
                    BottomTab::Logs => BottomTab::Timeline,
                };
            }

            KeyCode::Char('h') | KeyCode::Char('H') => {
                self.mode = Mode::Help;
            }

            _ => {}
        }

        false
    }

    fn handle_help_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('H') => {
                self.mode = Mode::Normal;
            }
            _ => {}
        }

        false
    }

    fn handle_scenario_key(&mut self, key: KeyEvent, cmd_tx: &Sender<SimCommand>) -> bool {
        let presets = scenario::presets();

        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
            }
            KeyCode::Up => {
                if self.selected_scenario > 0 {
                    self.selected_scenario -= 1;
                }
            }
            KeyCode::Down => {
                if self.selected_scenario + 1 < presets.len() {
                    self.selected_scenario += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(preset) = presets.get(self.selected_scenario) {
                    let _ = cmd_tx.send(SimCommand::ApplyScenario(preset.id));
                    self.current_scenario = Some(preset.id);
                    self.selected_trace = 0;
                }
                self.mode = Mode::Normal;
            }
            _ => {}
        }

        false
    }

    fn handle_input_key(&mut self, key: KeyEvent, cmd_tx: &Sender<SimCommand>) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.input_target = InputTarget::None;
                self.input_buf.clear();
            }

            KeyCode::Enter => match self.input_target {
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
            },

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

    pub fn current_scenario_preset(&self) -> &'static crate::scenario::ScenarioPreset {
        scenario::preset(
            self.current_scenario
                .unwrap_or_else(scenario::default_scenario),
        )
    }

    pub fn clamp_selection(&mut self, trace_count: usize) {
        if trace_count == 0 {
            self.selected_trace = 0;
        } else if self.selected_trace >= trace_count {
            self.selected_trace = trace_count - 1;
        }
    }
}
