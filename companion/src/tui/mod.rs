use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::watch;

use crate::diagnostics::state::SharedState;
use crate::runtime::CompanionCommand;

mod app;
mod ui;

use app::{App, UiAction};

pub fn run(
    shared: Arc<Mutex<SharedState>>,
    shutdown_tx: watch::Sender<bool>,
    cmd_tx: std::sync::mpsc::Sender<CompanionCommand>,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let result = run_loop(&mut terminal, &mut app, &shared, &cmd_tx);

    let _ = shutdown_tx.send(true);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    shared: &Arc<Mutex<SharedState>>,
    cmd_tx: &std::sync::mpsc::Sender<CompanionCommand>,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| {
            let state = shared.lock().unwrap();
            ui::render(frame, app, &state);
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                let peers = shared.lock().unwrap().peers.clone();
                match app.handle_key(key, peers.len()) {
                    UiAction::Quit => {
                        break;
                    }
                    UiAction::EnrollSelected => {
                        if let Some(peer) = peers.get(app.selected_peer.min(peers.len().saturating_sub(1))) {
                            let _ = cmd_tx.send(CompanionCommand::EnrollSelected(peer.id.clone()));
                        }
                    }
                    UiAction::None => {}
                }
            }
        }
    }
    Ok(())
}
