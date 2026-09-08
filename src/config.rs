use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

pub type DynError = Box<dyn std::error::Error + Send + Sync>;
pub type AppConfig = Config;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub mode: String, // "server", "client" или "ask"
    pub server: ServerConfig,
    pub client: ClientConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, DynError> {
        let path_str = path.to_str().unwrap_or("config.toml");
        load_or_create_config(path_str)
    }

    pub fn is_server(&self) -> bool {
        self.mode.eq_ignore_ascii_case("server")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub wallet_path: String,
    pub tun_enabled: bool,
    pub tun_name: String,
    pub tun_ip: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    pub server_host: String,
    pub routing_mode: String, // "socks5" или "tun"
    pub socks_bind_addr: String,
    pub tun_name: String,
    pub tun_ip: String,
    pub tun_gateway: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: "ask".to_string(),
            server: ServerConfig {
                bind_addr: "0.0.0.0:8888".to_string(),
                wallet_path: "server.wallet".to_string(),
                tun_enabled: true,
                tun_name: "typroxy-srv".to_string(),
                tun_ip: "10.8.0.1".to_string(),
            },
            client: ClientConfig {
                server_host: "127.0.0.1:8888".to_string(),
                routing_mode: "socks5".to_string(),
                socks_bind_addr: "127.0.0.1:1080".to_string(),
                tun_name: "typroxy-tun".to_string(),
                tun_ip: "10.8.0.2".to_string(),
                tun_gateway: "10.8.0.1".to_string(),
            },
        }
    }
}

pub fn load_or_create_config(path: &str) -> Result<Config, DynError> {
    if !Path::new(path).exists() {
        let annotated_toml = r#"# Режим: "server", "client" или "ask"
        mode = "ask"

        [server]
        bind_addr = "0.0.0.0:8888"
        wallet_path = "server.wallet"
        tun_enabled = true
        tun_name = "typroxy-srv"
        tun_ip = "10.8.0.1"

        [client]
        server_host = "127.0.0.1:8888"
        # routing_mode: "socks5" или "tun"
        routing_mode = "socks5"
        socks_bind_addr = "127.0.0.1:1080"
        tun_name = "typroxy-tun"
        tun_ip = "10.8.0.2"
        tun_gateway = "10.8.0.1"
        "#;
        fs::write(path, annotated_toml)?;
        println!("[!] Конфигурационный файл '{}' создан.", path);
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
            println!("=== Выбор режима TyProxy ===");
            println!("[1] Host Server (Сервер)");
            println!("[2] Connect Client (Клиент)");
            print!("Выберите [1/2]: ");
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
