//! Constellation mesh simulator with interactive TUI.
//!
//! Run with:
//!   cargo run -p sim

use sim::runtime::SimRuntime;
use sim::{scenario, tui, tui_logger};

fn main() {
    tui_logger::init(log::LevelFilter::Info);

    let runtime = SimRuntime::from_scenario(scenario::default_scenario());
    runtime.log_startup();

    if let Err(e) = tui::run(
        runtime.tui_state.clone(),
        runtime.sim_config.clone(),
        runtime.cmd_tx.clone(),
    ) {
        eprintln!("TUI error: {e}");
        std::process::exit(1);
    }
}
