pub mod server;

pub mod dns;

pub mod db;

pub mod shutdown;

pub const DEFAULT_PORT:u16 = 8853;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub type Result<T> = std::result::Result<T, Error>;

pub static mut GUARD: Option<tracing_appender::non_blocking::WorkerGuard> = None;