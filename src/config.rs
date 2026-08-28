use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub mode: String, // "server", "client" или "ask"
    pub server: ServerConfig,
    pub client: ClientConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub wallet_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    pub server_host: String,
    pub expected_server_id: Option<u32>,
    pub socks_bind_addr: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: "ask".to_string(),
            server: ServerConfig {
                bind_addr: "0.0.0.0:8888".to_string(),
                wallet_path: "server.wallet".to_string(),
            },
            client: ClientConfig {
                server_host: "127.0.0.1:8888".to_string(),
                expected_server_id: None,
                socks_bind_addr: "127.0.0.1:1080".to_string(),
            },
        }
    }
}

pub fn load_or_create_config(path: &str) -> Result<Config, DynError> {
    if !Path::new(path).exists() {
        let annotated_toml = format!(
            "# Режим запуска: \"server\", \"client\" или \"ask\" (спрашивать при старте)\n\
            mode = \"ask\"\n\n\
            [server]\n\
            bind_addr = \"0.0.0.0:8888\"\n\
            wallet_path = \"server.wallet\"\n\n\
            [client]\n\
            server_host = \"127.0.0.1:8888\"\n\
            # expected_server_id = 945928  # Раскомментируйте для проверки ID сервера\n\
            socks_bind_addr = \"127.0.0.1:1080\"\n"
        );

        fs::write(path, annotated_toml)?;

        println!("[!] Вы запустили программу в первый раз.");
        println!("[!] Файл конфигурации '{}' был автоматически создан.", path);
        println!("[!] Отредактируйте конфигурационный файл и запустите снова.");
        std::process::exit(0);
    }

    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

pub fn select_mode(configured_mode: &str) -> String {
    match configured_mode.to_lowercase().as_str() {
        "server" => "server".to_string(),
        "client" => "client".to_string(),
        _ => {
            println!("=== Выберите режим работы TyProxy ===");
            println!("[1] Host Server (Запустить сервер)");
            println!("[2] Connect Server (Запустить SOCKS5 клиент)");
            print!("Ваш выбор [1/2]: ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();

            match input.trim() {
                "2" => "client".to_string(),
                _ => "server".to_string(),
            }
        }
    }
}