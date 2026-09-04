mod client;
mod config;
mod crypto;
mod modules;
mod server;

use config::DynError;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Не удалось установить CryptoProvider для rustls");

    let cfg = config::load_or_create_config("config.toml")?;
    let selected_mode = config::select_mode(&cfg.mode);

    if selected_mode == "client" {
        client::run_client(cfg.client).await?;
    } else {
        server::run_server(cfg.server).await?;
    }

    Ok(())
}
