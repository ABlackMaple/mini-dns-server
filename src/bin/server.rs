use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::Parser;
use config::ConfigError;
use mini_dns_server::server;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use mini_dns_server::{ DEFAULT_PORT, GUARD};
use mini_dns_server::Result;
use tokio::signal;
use tracing::{error, info};
use tracing_appender::rolling::RollingFileAppender;
use tracing_appender::rolling::Rotation;

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(rename = "listen")]
    pub listen_addr: String,

    #[serde(rename = "upstream")]
    pub upstream_servers: Option<Vec<String>>,

    pub port: u16,

    #[serde(rename = "log-path")]
    pub log_path: PathBuf,

    #[serde(rename = "max-connections")]
    pub max_connections: usize,

    #[serde(rename = "max-cache-size")]
    pub max_cache_size: usize,

    #[serde(rename = "log-level")]
    pub log_level: String,

    #[serde(rename = "hosts-path")]
    pub db_path: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            upstream_servers: Some(vec!["114.114.114.114:53".to_string()]),
            port: DEFAULT_PORT,
            log_path: PathBuf::from("logs"),
            max_connections: 100,
            max_cache_size: 1000,
            log_level: "info".to_string(),
            db_path: Some("hosts".to_string()),
        }
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "config.toml")]
    config: Option<PathBuf>,

    #[arg(long)]
    listen_addr: Option<String>,

    #[arg(short, long)]
    port: Option<u16>,

    #[arg(long, value_delimiter = ',')]
    upstream: Option<Vec<String>>,

    #[arg(long)]
    log_path: Option<PathBuf>,

    #[arg(long)]
    max_connections: Option<usize>,

    #[arg(long)]
    max_cache_size: Option<usize>,

    #[arg(long)]
    log_level: Option<String>,

    #[arg(long, default_value = "hosts")]
    db_path: Option<String>,
}

fn load_config(path: Option<&Path>) -> std::result::Result<Config, ConfigError> {
    let cfg = config::Config::builder();

    let cfg = if let Some(path) = path {
        if path.exists() {
            cfg.add_source(config::File::from(path))
        } else {
            eprintln!("Config file not found: {:?}", path);
            cfg
        }
    } else {
        cfg
    };

    match cfg.build() {
        Ok(config) => {
            let config  = config.try_deserialize();
            if config.is_err() {
                eprintln!("Failed to parse config file: {:?}", config);
                return Err(config.err().unwrap());
            }
            let config = config.unwrap();
            println!("Loaded config: {:?}", config);
            Ok(config)
        },
        Err(e) => {
            eprintln!("Failed to load config: {:?}", e);
            Err(e)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut config = load_config(args.config.as_deref()).unwrap_or_default();

    update_config(&mut config, &args);
    
    let log_path = config.log_path;
    let log_level = config.log_level;
    set_up_logging(log_path.to_str(), &log_level)?;

    info!("Logging initialized with level: '{}'", log_level);
    info!("Log path: '{:?}'", log_path);
    info!("Max connections: '{}'", config.max_connections);
    info!("Max cache size: '{}'", config.max_cache_size);
    info!("Upstream servers: '{:?}'", config.upstream_servers);

    let port = config.port;    
    let listen_addr = config.listen_addr.clone();
    let upstream_servers = config.upstream_servers.clone().unwrap();

    let upstream: Vec<SocketAddr> = upstream_servers
        .iter()
        .map(|s| match SocketAddr::from_str(&s) {
            Ok(addr) => {addr},
            Err(_) => {
                error!("Invalid upstream server address: '{}'", s);
                std::process::exit(1);
            },
        })
        .collect::<Vec<_>>();

    info!("starting server on port {}", port);
    let socket = UdpSocket::bind(format!("{}:{}",listen_addr, port)).await?;
    server::run(socket, signal::ctrl_c(), config.max_connections, config.max_cache_size, upstream, config.db_path).await;

    Ok(())
}

fn update_config(config: &mut Config, args: &Args) {
    if let Some(listen_addr) = &args.listen_addr {
        config.listen_addr = listen_addr.clone();
    }
    if let Some(port) = args.port {
        config.port = port;
    }
    if let Some(upstream) = &args.upstream {
        config.upstream_servers = Some(upstream.clone());
    }
    if let Some(log_path) = &args.log_path {
        config.log_path = log_path.clone();
    }
    if let Some(max_connections) = args.max_connections {
        config.max_connections = max_connections;
    }
    if let Some(max_cache_size) = args.max_cache_size {
        config.max_cache_size = max_cache_size;
    }
    if let Some(log_level) = &args.log_level {
        config.log_level = log_level.clone();
    }
}

fn set_up_logging(log_path: Option<&str>, log_level: &str) -> mini_dns_server::Result<()>{
    use tracing_subscriber::fmt::{ self, time::LocalTime};
    let file_appender = RollingFileAppender::new(Rotation::DAILY, log_path.unwrap_or("logs"), "mini-dns.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    unsafe {
        GUARD = Some(_guard)
    }

    fmt::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_max_level(log_level.parse().unwrap_or(tracing::Level::INFO))
        .with_timer(LocalTime::rfc_3339())
        .try_init()
}
