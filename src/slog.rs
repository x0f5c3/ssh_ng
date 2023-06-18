pub use log;

use tracing::{LevelFilter, Log, Metadata, Record};

pub(crate) static SLOG: Slog = Slog;

pub struct Slog;

impl Slog {
    fn init(level: LevelFilter) {
        if let Err(e) = tracing::set_logger(&SLOG) {
            tracing::error!(
                "initialization log error, the error information is: {:?}",
                e
            );
            return;
        }
        tracing::set_max_level(level);
    }

    pub fn default() {
        Stracing::init(LevelFilter::Info)
    }

    pub fn debug() {
        Stracing::init(LevelFilter::Trace)
    }
}

impl Log for Slog {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() != LevelFilter::Off
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("[SSH]-[{}]: {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}
