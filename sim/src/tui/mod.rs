//! TUI entry point — runs on the main thread using crossterm + ratatui.

use std::io;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;
use std::time::Duration;

use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use crate::sim_state::{SimCommand, SimConfig, TuiState};

mod app;
mod ui;

pub use app::App;

pub fn run(
    tui_state: Arc<Mutex<TuiState>>,
    sim_config: Arc<Mutex<SimConfig>>,
    cmd_tx: Sender<SimCommand>,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let result = run_loop(&mut terminal, &mut app, &tui_state, &sim_config, &cmd_tx);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    tui_state: &Arc<Mutex<TuiState>>,
    sim_config: &Arc<Mutex<SimConfig>>,
    cmd_tx: &Sender<SimCommand>,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| {
            // Grab snapshots of shared state for this render frame.
            let state = tui_state.lock().unwrap();
            let config = sim_config.lock().unwrap();
            ui::render(f, app, &state, &config);
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if app.handle_key(key, sim_config, cmd_tx) {
                    break;
                }
            }
        }
    }

    Ok(())
}
