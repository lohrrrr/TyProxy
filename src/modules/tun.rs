use crate::config::ClientConfig;
use crate::crypto::DynError;
use crate::modules::socks5::TlsWriterArc;
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

pub type TunWriterArc = Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>;

pub async fn run_tun_module(
    cfg: ClientConfig,
    tls_writer: TlsWriterArc,
    tun_tx_slot: TunWriterArc,
) -> Result<(), DynError> {
    let dev = {
        let mut tun_cfg = tun::Configuration::default();
        let tun_ip: std::net::Ipv4Addr = cfg.tun_ip.parse()?;
        let tun_gw: std::net::Ipv4Addr = cfg.tun_gateway.parse()?;

        tun_cfg
        .name(&cfg.tun_name)
        .address(tun_ip)
        .netmask((255, 255, 255, 0))
        .destination(tun_gw)
        .up();

        #[cfg(target_os = "linux")]
        tun_cfg.platform(|c| {
            c.packet_information(false);
        });

        tun::create_as_async(&tun_cfg)?
    };

    println!("[+] TUN интерфейс '{}' успешно поднят с IP {}", cfg.tun_name, cfg.tun_ip);

    setup_routes(&cfg)?;

    let (mut tun_reader, mut tun_writer) = tokio::io::split(dev);

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    *tun_tx_slot.lock().await = Some(tx);

    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            if tun_writer.write_all(&packet).await.is_err() {
                break;
            }
        }
    });

    let mut buf = [0u8; 65535];
    loop {
        let n = match tun_reader.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            _ => break,
        };

        let packet = crate::client::build_packet(2, 0, "", &buf[..n]);
        if tls_writer.lock().await.write_all(&packet).await.is_err() {
            eprintln!("[-] Ошибка отправки TUN пакета на сервер");
            break;
        }
    }

    Ok(())
}

fn setup_routes(cfg: &ClientConfig) -> Result<(), DynError> {
    let server_ip = cfg.server_host.split(':').next().unwrap_or("");
    println!("[*] Настройка маршрутизации через TUN '{}'...", cfg.tun_name);

    #[cfg(target_os = "linux")]
    {
        let default_gw_out = Command::new("sh")
        .arg("-c")
        .arg("ip route show default | awk '/default/ {print $3}'")
        .output()?;
        let default_gw = String::from_utf8_lossy(&default_gw_out.stdout).trim().to_string();

        if !default_gw.is_empty() && !server_ip.is_empty() {
            let _ = Command::new("ip").args(["route", "add", server_ip, "via", &default_gw]).output();
        }

        let _ = Command::new("ip").args(["route", "add", "0.0.0.0/1", "dev", &cfg.tun_name]).output();
        let _ = Command::new("ip").args(["route", "add", "128.0.0.0/1", "dev", &cfg.tun_name]).output();
        println!("[+] Системные маршруты Linux обновлены (трафик перехвачен).");
    }

    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("route").args(["add", server_ip, "mask", "255.255.255.255"]).output();
        let _ = Command::new("route").args(["add", "0.0.0.0", "mask", "128.0.0.0", &cfg.tun_gateway]).output();
        let _ = Command::new("route").args(["add", "128.0.0.0", "mask", "128.0.0.0", &cfg.tun_gateway]).output();
        println!("[+] Системные маршруты Windows обновлены.");
    }

    Ok(())
}
