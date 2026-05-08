//! TUI application state and keyboard event handling for the trace-centric UI.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use crossterm::event::{KeyCode, KeyEvent};

use routing_core::node::roles::Capabilities;

use crate::config_ops;
use crate::export::{self, ExportContext};
use crate::scenario::{self, ScenarioId};
use crate::sim_state::{MessageKind, SimCommand, SimConfig, TraceFilter, TuiState, MAX_NODES};
use crate::tui_logger;

#[derive(Clone, Copy, PartialEq)]
pub enum ViewMode {
    Trace,
    Nodes,
    Links,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Normal,
    InputMessage,
    InputDropProb,
    ScenarioSelect,
    Help,
}

#[derive(Clone, Copy, PartialEq)]
pub enum InputTarget {
    None,
    DropProb {
        from: usize,
        to: usize,
    },
    MessageFrom,
    MessageTo,
    MessageBody {
        from: usize,
        to: usize,
        is_broadcast: bool,
    },
}

#[derive(Clone, Copy, PartialEq)]
pub enum BottomTab {
    Timeline,
    Graph,
    Packet,
    Logs,
}

pub struct App {
    pub view_mode: ViewMode,
    pub mode: Mode,
    pub input_buf: String,
    pub input_target: InputTarget,
    pub pending_msg_from: usize,
    pub pending_msg_to: usize,
    pub bottom_tab: BottomTab,
    pub selected_trace: usize,
    pub selected_node: usize,
    pub selected_link_node: usize,
    pub selected_link_peer_row: usize,
    pub trace_filter: TraceFilter,
    pub selected_scenario: usize,
    pub current_scenario: Option<ScenarioId>,
}

impl App {
    pub fn new() -> Self {
        Self {
            view_mode: ViewMode::Trace,
            mode: Mode::Normal,
            input_buf: String::new(),
            input_target: InputTarget::None,
            pending_msg_from: 0,
            pending_msg_to: 1,
            bottom_tab: BottomTab::Timeline,
            selected_trace: 0,
            selected_node: 0,
            selected_link_node: 0,
            selected_link_peer_row: 0,
            trace_filter: TraceFilter::All,
            selected_scenario: 0,
            current_scenario: Some(scenario::default_scenario()),
        }
    }

    /// Returns `true` if the app should quit.
    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        sim_config: &Arc<Mutex<SimConfig>>,
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
            return self.handle_input_key(key, sim_config, cmd_tx);
        }

        let trace_count = tui_state
            .lock()
            .unwrap()
            .filtered_trace_indices(self.trace_filter)
            .len();

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,

            KeyCode::Char('n') | KeyCode::Char('N') => {
                self.view_mode = match self.view_mode {
                    ViewMode::Trace => ViewMode::Nodes,
                    ViewMode::Nodes => ViewMode::Links,
                    ViewMode::Links => ViewMode::Trace,
                };
            }

            KeyCode::Up => match self.view_mode {
                ViewMode::Trace => {
                    if self.selected_trace > 0 {
                        self.selected_trace -= 1;
                    }
                }
                ViewMode::Nodes => {
                    if self.selected_node > 0 {
                        self.selected_node -= 1;
                    }
                }
                ViewMode::Links => {
                    if self.selected_link_peer_row > 0 {
                        self.selected_link_peer_row -= 1;
                    }
                }
            },

            KeyCode::Down => match self.view_mode {
                ViewMode::Trace => {
                    if self.selected_trace + 1 < trace_count {
                        self.selected_trace += 1;
                    }
                }
                ViewMode::Nodes => {
                    let n_active = sim_config.lock().unwrap().n_active;
                    if self.selected_node + 1 < n_active {
                        self.selected_node += 1;
                    }
                }
                ViewMode::Links => {
                    let n_active = sim_config.lock().unwrap().n_active;
                    if self.selected_link_peer_row + 2 < n_active {
                        self.selected_link_peer_row += 1;
                    }
                }
            },

            KeyCode::Left => {
                if self.view_mode == ViewMode::Links {
                    if self.selected_link_node > 0 {
                        self.selected_link_node -= 1;
                        self.selected_link_peer_row = 0;
                    }
                }
            }

            KeyCode::Right => {
                if self.view_mode == ViewMode::Links {
                    let n_active = sim_config.lock().unwrap().n_active;
                    if self.selected_link_node + 1 < n_active {
                        self.selected_link_node += 1;
                        self.selected_link_peer_row = 0;
                    }
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
                    BottomTab::Timeline => BottomTab::Graph,
                    BottomTab::Graph => BottomTab::Packet,
                    BottomTab::Packet => BottomTab::Logs,
                    BottomTab::Logs => BottomTab::Timeline,
                };
            }

            KeyCode::Char('f') | KeyCode::Char('F') if self.view_mode == ViewMode::Trace => {
                self.trace_filter = match self.trace_filter {
                    TraceFilter::All => TraceFilter::Directed,
                    TraceFilter::Directed => TraceFilter::Broadcast,
                    TraceFilter::Broadcast => TraceFilter::All,
                };
                self.selected_trace = 0;
            }

            KeyCode::Char('h') | KeyCode::Char('H') => {
                self.mode = Mode::Help;
            }

            KeyCode::Char('e') | KeyCode::Char('E') if self.view_mode == ViewMode::Trace => {
                self.export_diagnostics(tui_state, sim_config);
            }

            KeyCode::Char(' ') if self.view_mode == ViewMode::Links => {
                self.toggle_selected_link(sim_config);
            }

            KeyCode::Char('p') | KeyCode::Char('P') if self.view_mode == ViewMode::Links => {
                if let Some((from, to)) = self.selected_link_pair(sim_config) {
                    self.mode = Mode::InputDropProb;
                    self.input_buf.clear();
                    self.input_target = InputTarget::DropProb { from, to };
                }
            }

            _ if self.view_mode == ViewMode::Nodes => {
                self.handle_node_edit_key(key, sim_config);
            }

            _ => {}
        }

        false
    }

    fn handle_node_edit_key(&mut self, key: KeyEvent, sim_config: &Arc<Mutex<SimConfig>>) {
        let mut cfg = sim_config.lock().unwrap();
        if self.selected_node >= cfg.n_active {
            return;
        }
        match key.code {
            KeyCode::Char(' ') => {
                config_ops::update_node_behavior(&mut cfg, self.selected_node, |behavior| {
                    behavior.advertise = !behavior.advertise;
                });
            }
            KeyCode::Char('t') | KeyCode::Char('T') => {
                let next_type = cfg.node_types[self.selected_node].cycle();
                config_ops::set_node_type(&mut cfg, self.selected_node, next_type);
            }
            KeyCode::Char('1') => {
                config_ops::toggle_capability(&mut cfg, self.selected_node, Capabilities::ROUTE)
            }
            KeyCode::Char('2') => {
                config_ops::toggle_capability(&mut cfg, self.selected_node, Capabilities::STORE)
            }
            KeyCode::Char('3') => config_ops::toggle_capability(
                &mut cfg,
                self.selected_node,
                Capabilities::APPLICATION,
            ),
            KeyCode::Char('4') => {
                config_ops::toggle_capability(&mut cfg, self.selected_node, Capabilities::BRIDGE)
            }
            KeyCode::Char('5') => config_ops::toggle_capability(
                &mut cfg,
                self.selected_node,
                Capabilities::LOW_ENERGY,
            ),
            KeyCode::Char('6') => {
                config_ops::toggle_capability(&mut cfg, self.selected_node, Capabilities::MOBILE)
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                config_ops::update_node_behavior(&mut cfg, self.selected_node, |behavior| {
                    behavior.advertise = !behavior.advertise;
                })
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                config_ops::update_node_behavior(&mut cfg, self.selected_node, |behavior| {
                    behavior.scan = !behavior.scan;
                })
            }
            KeyCode::Char('i') | KeyCode::Char('I') => {
                config_ops::update_node_behavior(&mut cfg, self.selected_node, |behavior| {
                    behavior.initiate_h2h = !behavior.initiate_h2h;
                })
            }
            KeyCode::Char('o') | KeyCode::Char('O') => {
                config_ops::update_node_behavior(&mut cfg, self.selected_node, |behavior| {
                    behavior.respond_h2h = !behavior.respond_h2h;
                })
            }
            KeyCode::Char('e') | KeyCode::Char('E') => {
                config_ops::update_node_behavior(&mut cfg, self.selected_node, |behavior| {
                    behavior.emit_sensor = !behavior.emit_sensor;
                })
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                if self.selected_node + 1 == cfg.n_active && cfg.n_active > 1 {
                    let next_n_active = cfg.n_active - 1;
                    config_ops::set_n_active(&mut cfg, next_n_active);
                }
            }
            KeyCode::Char('z') | KeyCode::Char('Z') => {
                if cfg.n_active < MAX_NODES {
                    let next_n_active = cfg.n_active + 1;
                    config_ops::set_n_active(&mut cfg, next_n_active);
                    self.selected_node = cfg.n_active - 1;
                }
            }
            _ => {}
        }
    }

    fn selected_link_pair(&self, sim_config: &Arc<Mutex<SimConfig>>) -> Option<(usize, usize)> {
        let cfg = sim_config.lock().unwrap();
        if self.selected_link_node >= cfg.n_active {
            return None;
        }
        link_row_to_peer(
            self.selected_link_node,
            self.selected_link_peer_row,
            cfg.n_active,
        )
        .map(|peer| (self.selected_link_node, peer))
    }

    fn toggle_selected_link(&mut self, sim_config: &Arc<Mutex<SimConfig>>) {
        let Some((from, to)) = self.selected_link_pair(sim_config) else {
            return;
        };
        let mut cfg = sim_config.lock().unwrap();
        config_ops::toggle_link(&mut cfg, from, to);
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

            KeyCode::Enter => match self.input_target {
                InputTarget::DropProb { .. } => {
                    self.apply_drop_prob_input(sim_config);
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
                    let trimmed = self.input_buf.trim();
                    if trimmed.eq_ignore_ascii_case("all") || trimmed == "*" {
                        self.pending_msg_to = MAX_NODES;
                        self.input_target = InputTarget::MessageBody {
                            from: self.pending_msg_from,
                            to: MAX_NODES,
                            is_broadcast: true,
                        };
                        self.input_buf.clear();
                    } else if let Ok(to) = trimmed.parse::<usize>() {
                        if to < MAX_NODES {
                            self.pending_msg_to = to;
                            self.input_target = InputTarget::MessageBody {
                                from: self.pending_msg_from,
                                to,
                                is_broadcast: false,
                            };
                            self.input_buf.clear();
                        }
                    }
                }

                InputTarget::MessageBody { from, to, .. } => {
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

    pub fn apply_drop_prob_input(&mut self, sim_config: &Arc<Mutex<SimConfig>>) {
        if let InputTarget::DropProb { from, to } = self.input_target {
            if let Ok(prob) = self.input_buf.trim().parse::<u8>() {
                config_ops::set_drop_prob(&mut sim_config.lock().unwrap(), from, to, prob);
            }
        }
    }

    pub fn current_scenario_preset(&self) -> &'static crate::scenario::ScenarioPreset {
        scenario::preset(
            self.current_scenario
                .unwrap_or_else(scenario::default_scenario),
        )
    }

    fn export_diagnostics(
        &self,
        tui_state: &Arc<Mutex<TuiState>>,
        sim_config: &Arc<Mutex<SimConfig>>,
    ) {
        let logs = tui_logger::snapshot_logs();
        let state = tui_state.lock().unwrap().clone();
        let config = sim_config.lock().unwrap().clone();
        let scenario = self.current_scenario_preset();

        match export::export_diagnostics(
            &state,
            &config,
            ExportContext {
                scenario,
                trace_filter: self.trace_filter,
                selected_trace_index: self.selected_trace,
                logs: &logs,
            },
        ) {
            Ok(path) => log::info!("Exported diagnostics to {}", path.display()),
            Err(err) => log::error!("Failed to export diagnostics: {err}"),
        }
    }

    pub fn clamp_selection(&mut self, trace_count: usize, n_active: usize) {
        if trace_count == 0 {
            self.selected_trace = 0;
        } else if self.selected_trace >= trace_count {
            self.selected_trace = trace_count - 1;
        }

        if n_active == 0 {
            self.selected_node = 0;
            self.selected_link_node = 0;
            self.selected_link_peer_row = 0;
        } else if self.selected_node >= n_active {
            self.selected_node = n_active - 1;
            self.selected_link_node = self.selected_link_node.min(n_active - 1);
        }
        self.selected_link_peer_row = self.selected_link_peer_row.min(n_active.saturating_sub(2));
    }
}

fn link_row_to_peer(node_idx: usize, row: usize, n_active: usize) -> Option<usize> {
    let mut r = 0usize;
    for i in 0..n_active {
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
