//! In-process log collector for the TUI.
//!
//! Replaces `env_logger` so that log output goes into a ring buffer that the
//! TUI renders in the "Logs" tab, instead of being printed to stderr and
//! corrupting the terminal UI.

use std::collections::VecDeque;
use std::sync::Mutex;

use log::{LevelFilter, Log, Metadata, Record};

const MAX_LOGS: usize = 500;

static LOG_BUF: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Return the last `n` log lines (oldest first).
pub fn get_logs(n: usize) -> Vec<String> {
    let buf = LOG_BUF.lock().unwrap();
    buf.iter().rev().take(n).rev().cloned().collect()
}

struct TuiLogger;

impl Log for TuiLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let msg = format!("[{:<5}] {}", record.level(), record.args());
        if let Ok(mut buf) = LOG_BUF.try_lock() {
            if buf.len() >= MAX_LOGS {
                buf.pop_front();
            }
            buf.push_back(msg);
        }
    }

    fn flush(&self) {}
}

static LOGGER: TuiLogger = TuiLogger;

pub fn init(level: LevelFilter) {
    log::set_logger(&LOGGER).ok();
    log::set_max_level(level);
}
