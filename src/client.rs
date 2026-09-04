use crate::config::ClientConfig;
use crate::crypto::{DynError, NoCertificateVerification};
use crate::modules::socks5::{self, ClientSocketsPool, TlsWriterArc, UdpRelayPool};
use crate::modules::tun::{self, TunWriterArc};

use rustls::pki_types::ServerName;
use rustls::ClientConfig as RustlsClientConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

pub async fn run_client(cfg: ClientConfig) -> Result<(), DynError> {
    println!(
        "[*] Подключение к TLS TyProxy серверу ({})",
        cfg.server_host
    );

    let mut crypto = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    crypto.alpn_protocols = vec![b"typroxy".to_vec()];

    let connector = TlsConnector::from(Arc::new(crypto));
    let stream = TcpStream::connect(&cfg.server_host).await?;

    let domain = ServerName::try_from("typroxy")?.to_owned();
    let tls_stream = connector.connect(domain, stream).await?;

    println!("[+] Защищенное TLS-соединение установлено!");

    let (mut reader, writer) = tokio::io::split(tls_stream);
    let writer_arc: TlsWriterArc = Arc::new(Mutex::new(writer));

    let active_socks: ClientSocketsPool = Arc::new(Mutex::new(HashMap::new()));
    let udp_relays: UdpRelayPool = Arc::new(Mutex::new(HashMap::new()));
    let tun_sender_slot: TunWriterArc = Arc::new(Mutex::new(None));

    let routing_mode = cfg.routing_mode.to_lowercase();
    match routing_mode.as_str() {
        "tun" => {
            println!("[*] Выбран режим перехвата трафика: TUN");
            let tun_slot_clone = tun_sender_slot.clone();
            let w_arc = writer_arc.clone();
            let cfg_clone = cfg.clone();
            tokio::spawn(async move {
                if let Err(e) = tun::run_tun_module(cfg_clone, w_arc, tun_slot_clone).await {
                    eprintln!("[-] Ошибка модуля TUN: {}. Проверьте root/sudo права!", e);
                }
            });
        }
        _ => {
            println!("[*] Выбран режим перехвата трафика: SOCKS5");
            let socks_bind = cfg.socks_bind_addr.clone();
            let w_arc = writer_arc.clone();
            let socks_pool = active_socks.clone();
            let udp_pool = udp_relays.clone();
            tokio::spawn(async move {
                let _ = socks5::run_socks5_module(socks_bind, w_arc, socks_pool, udp_pool).await;
            });
        }
    }

    loop {
        let mut len_buf = [0u8; 2];
        if reader.read_exact(&mut len_buf).await.is_err() {
            println!("[-] Потеряно соединение с сервером.");
            break;
        }
        let frame_len = u16::from_be_bytes(len_buf) as usize;

        let mut frame_buf = vec![0u8; frame_len];
        if reader.read_exact(&mut frame_buf).await.is_err() {
            break;
        }

        if let Some((pkt_type, conn_id, target_key, payload)) = parse_frame(&frame_buf) {
            match pkt_type {
                0 => {
                    // TCP
                    let mut pool = active_socks.lock().await;
                    if let Some(socks_writer) = pool.get_mut(&conn_id) {
                        if socks_writer.write_all(&payload).await.is_err() {
                            pool.remove(&conn_id);
                        }
                    }
                }
                1 => {
                    // UDP
                    let pool = udp_relays.lock().await;
                    if let Some((udp_socket, client_addr_arc)) = pool.get(&conn_id) {
                        if let Some(client_addr) = *client_addr_arc.lock().await {
                            let mut socks_udp_frame = Vec::with_capacity(10 + payload.len());
                            socks_udp_frame
                                .extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1]);
                            let port = target_key
                                .rsplit(':')
                                .next()
                                .and_then(|p| p.parse::<u16>().ok())
                                .unwrap_or(0);
                            socks_udp_frame.extend_from_slice(&port.to_be_bytes());
                            socks_udp_frame.extend_from_slice(&payload);
                            let _ = udp_socket.send_to(&socks_udp_frame, client_addr).await;
                        }
                    }
                }
                2 => {
                    // TUN Packet
                    let slot = tun_sender_slot.lock().await;
                    if let Some(tx) = &*slot {
                        let _ = tx.send(payload).await;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

pub fn build_packet(pkt_type: u8, conn_id: u64, target_key: &str, payload: &[u8]) -> Vec<u8> {
    let meta_bytes = target_key.as_bytes();
    let meta_len = meta_bytes.len() as u16;
    let total_len = 1 + 8 + 2 + meta_bytes.len() + payload.len();

    let mut packet = Vec::with_capacity(2 + total_len);
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.push(pkt_type);
    packet.extend_from_slice(&conn_id.to_be_bytes());
    packet.extend_from_slice(&meta_len.to_be_bytes());
    packet.extend_from_slice(meta_bytes);
    packet.extend_from_slice(payload);
    packet
}

pub fn parse_frame(data: &[u8]) -> Option<(u8, u64, String, Vec<u8>)> {
    if data.len() < 11 {
        return None;
    }
    let pkt_type = data[0];
    let conn_id = u64::from_be_bytes(data[1..9].try_into().ok()?);
    let meta_len = u16::from_be_bytes([data[9], data[10]]) as usize;
    if data.len() < 11 + meta_len {
        return None;
    }

    let key = String::from_utf8_lossy(&data[11..11 + meta_len]).to_string();
    let payload = data[11 + meta_len..].to_vec();
    Some((pkt_type, conn_id, key, payload))
}
