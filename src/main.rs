mod client;
mod config;
mod crypto;
mod server;

use config::DynError;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    // Явно регистрируем ring как провайдер криптографии для rustls 0.23+
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Не удалось установить CryptoProvider для rustls");

    // 1. Загружаем или генерируем config.toml
    let cfg = config::load_or_create_config("config.toml")?;

    // 2. Интерактивно или по конфигу выбираем mode ("server" / "client")
    let selected_mode = config::select_mode(&cfg.mode);

    // 3. Запускаем нужную логику с соответствующей под-структурой конфига
    if selected_mode == "client" {
        client::run_client(cfg.client).await?;
    } else {
        server::run_server(cfg.server).await?;
    }

    Ok(())
}