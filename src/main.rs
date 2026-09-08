use clap::Parser;
use std::path::PathBuf;
use tokio::signal;

mod client;
mod config;
mod crypto;
mod modules;
mod server;

use config::{AppConfig, DynError};

#[derive(Parser, Debug)]
#[command(name = "typroxy", about = "TyProxy network tunnel")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Override role to run as server
    #[arg(long)]
    server: bool,
}

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let config = AppConfig::load(&cli.config)?;

    let is_server = if cli.server {
        true
    } else if config.mode.eq_ignore_ascii_case("ask") {
        config::select_mode(&config.mode) == "server"
    } else {
        config.is_server()
    };

    if is_server {
        tokio::select! {
            res = server::run_server(config.server) => {
                if let Err(e) = res {
                    eprintln!("Server error: {}", e);
                }
            }
            _ = signal::ctrl_c() => {
                println!("\nShutdown signal received. Stopping server...");
            }
        }
    } else {
        tokio::select! {
            res = client::run_client(config.client) => {
                if let Err(e) = res {
                    eprintln!("Client error: {}", e);
                }
            }
            _ = signal::ctrl_c() => {
                println!("\nShutdown signal received. Stopping client...");
            }
        }
    }

    Ok(())
}
