use crate::config::ClientConfig;
use crate::crypto::{DynError, NoCertificateVerification};

use rustls::pki_types::ServerName;
use rustls::ClientConfig as RustlsClientConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

type ClientSocketsPool = Arc<Mutex<HashMap<u64, tokio::net::tcp::OwnedWriteHalf>>>;
type UdpRelayPool = Arc<Mutex<HashMap<u64, (Arc<UdpSocket>, Arc<Mutex<Option<SocketAddr>>>)>>>;
type TlsWriterArc = Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>;

static CONN_COUNTER: AtomicU64 = AtomicU64::new(1);

pub async fn run_client(cfg: ClientConfig) -> Result<(), DynError> {
    println!("[*] Подключение к TLS TyProxy серверу ({})", cfg.server_host);

    let mut crypto = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    crypto.alpn_protocols = vec![b"typroxy".to_vec()];

    let connector = TlsConnector::from(Arc::new(crypto));
    let stream = TcpStream::connect(&cfg.server_host).await?;

    let domain = ServerName::try_from("typroxy")?.to_owned();
    let tls_stream = connector.connect(domain, stream).await?;

    println!("[+] Защищенное TLS 1.3 соединение успешно установлено!");

    let (mut reader, writer) = tokio::io::split(tls_stream);
    let writer_arc: TlsWriterArc = Arc::new(Mutex::new(writer));
    let active_socks: ClientSocketsPool = Arc::new(Mutex::new(HashMap::new()));
    let udp_relays: UdpRelayPool = Arc::new(Mutex::new(HashMap::new()));

    // --- SOCKS5 Server ---
    let socks_bind = cfg.socks_bind_addr.clone();
    let writer_clone = writer_arc.clone();
    let socks_pool_ref = active_socks.clone();
    let udp_pool_ref = udp_relays.clone();

    tokio::spawn(async move {
        let listener = match TcpListener::bind(&socks_bind).await {
            Ok(l) => {
                println!("[+] Локальный SOCKS5 прокси (TCP+UDP) запущен на {}", socks_bind);
                l
            }
            Err(e) => {
                eprintln!("[-] Ошибка привязки SOCKS5 к {}: {}", socks_bind, e);
                return;
            }
        };

        loop {
            if let Ok((socks_stream, peer_addr)) = listener.accept().await {
                let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed);
                println!("[SOCKS] [{}] Подключение от локального приложения {}", conn_id, peer_addr);
                let w_ref = writer_clone.clone();
                let p_ref = socks_pool_ref.clone();
                let u_ref = udp_pool_ref.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_socks_connection(conn_id, socks_stream, w_ref, p_ref, u_ref).await {
                        eprintln!("[-] [{}] Ошибка SOCKS-сессии: {}", conn_id, e);
                    }
                });
            }
        }
    });

    // --- Чтение ответов от сервера ---
    loop {
        let mut len_buf = [0u8; 2];
        if reader.read_exact(&mut len_buf).await.is_err() {
            println!("[-] Потеряно соединение с сервером.");
            break;
        }
        let frame_len = u16::from_be_bytes(len_buf) as usize;

        let mut frame_buf = vec![0u8; frame_len];
        if reader.read_exact(&mut frame_buf).await.is_err() {
            eprintln!("[-] Ошибка чтения фрейма от сервера");
            break;
        }

        if let Some((is_udp, conn_id, target_key, payload)) = parse_server_frame(&frame_buf) {
            if !is_udp {
                let mut pool = active_socks.lock().await;
                if let Some(socks_writer) = pool.get_mut(&conn_id) {
                    println!("[CLIENT RX] [{}] TCP Ответ от сервера для '{}' | Data: {} bytes", conn_id, target_key, payload.len());
                    if socks_writer.write_all(&payload).await.is_err() {
                        println!("[-] [{}] SOCKS клиент закрыл TCP соединение ({})", conn_id, target_key);
                        pool.remove(&conn_id);
                    }
                }
            } else {
                let pool = udp_relays.lock().await;
                if let Some((udp_socket, client_addr_arc)) = pool.get(&conn_id) {
                    if let Some(client_addr) = *client_addr_arc.lock().await {
                        println!("[CLIENT RX] [{}] UDP Ответ от сервера для '{}' -> {} | Data: {} bytes", conn_id, target_key, client_addr, payload.len());

                        let mut socks_udp_frame = Vec::with_capacity(10 + payload.len());
                        socks_udp_frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1]);
                        
                        let port = target_key.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
                        socks_udp_frame.extend_from_slice(&port.to_be_bytes());
                        socks_udp_frame.extend_from_slice(&payload);

                        let _ = udp_socket.send_to(&socks_udp_frame, client_addr).await;
                    }
                }
            }
        }
    }

    Ok(())
}

fn build_packet(is_udp: bool, conn_id: u64, target_key: &str, payload: &[u8]) -> Vec<u8> {
    let meta_bytes = target_key.as_bytes();
    let meta_len = meta_bytes.len() as u16;
    let total_len = 1 + 8 + 2 + meta_bytes.len() + payload.len();

    let mut packet = Vec::with_capacity(2 + total_len);
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.push(if is_udp { 1 } else { 0 });
    packet.extend_from_slice(&conn_id.to_be_bytes());
    packet.extend_from_slice(&meta_len.to_be_bytes());
    packet.extend_from_slice(meta_bytes);
    packet.extend_from_slice(payload);
    packet
}

fn parse_server_frame(data: &[u8]) -> Option<(bool, u64, String, Vec<u8>)> {
    if data.len() < 11 {
        return None;
    }
    let is_udp = data[0] == 1;
    let conn_id = u64::from_be_bytes(data[1..9].try_into().ok()?);
    let meta_len = u16::from_be_bytes([data[9], data[10]]) as usize;
    if data.len() < 11 + meta_len {
        return None;
    }

    let key = String::from_utf8_lossy(&data[11..11 + meta_len]).to_string();
    let payload = data[11 + meta_len..].to_vec();
    Some((is_udp, conn_id, key, payload))
}

async fn handle_socks_connection(
    conn_id: u64,
    socks_stream: TcpStream,
    tls_writer: TlsWriterArc,
    socks_pool: ClientSocketsPool,
    udp_pool: UdpRelayPool,
) -> Result<(), DynError> {
    let (mut socks_reader, mut socks_writer) = socks_stream.into_split();
    let mut buf = [0u8; 512];

    socks_reader.read_exact(&mut buf[..2]).await?;
    let nmethods = buf[1] as usize;
    socks_reader.read_exact(&mut buf[..nmethods]).await?;
    socks_writer.write_all(&[0x05, 0x00]).await?;

    socks_reader.read_exact(&mut buf[..4]).await?;
    let cmd = buf[1];

    if cmd == 0x01 {
        // --- TCP CONNECT ---
        let target_key = read_socks_address(&mut socks_reader, buf[3]).await?;
        println!("[SOCKS] [{}] TCP CONNECT запрос на target: {}", conn_id, target_key);

        socks_writer.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

        {
            let mut pool = socks_pool.lock().await;
            pool.insert(conn_id, socks_writer);
        }

        let mut payload_buf = [0u8; 4096];
        loop {
            let n = match socks_reader.read(&mut payload_buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };

            println!("[CLIENT TX] [{}] TCP Запрос к '{}' | Data: {} bytes", conn_id, target_key, n);
            let packet = build_packet(false, conn_id, &target_key, &payload_buf[..n]);
            if tls_writer.lock().await.write_all(&packet).await.is_err() {
                break;
            }
        }

        println!("[SOCKS] [{}] TCP Клиент закрыл соединение ({})", conn_id, target_key);
        let close_packet = build_packet(false, conn_id, &target_key, &[]);
        let _ = tls_writer.lock().await.write_all(&close_packet).await;

        {
            let mut pool = socks_pool.lock().await;
            pool.remove(&conn_id);
        }
    } else if cmd == 0x03 {
        // --- UDP ASSOCIATE ---
        let target_key = read_socks_address(&mut socks_reader, buf[3]).await?;
        println!("[SOCKS UDP] [{}] UDP ASSOCIATE запрос на target: {}", conn_id, target_key);

        let udp_listener = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = udp_listener.local_addr()?;

        let mut reply = vec![0x05, 0x00, 0x00, 0x01];
        match local_addr.ip() {
            std::net::IpAddr::V4(ip) => reply.extend_from_slice(&ip.octets()),
            _ => reply.extend_from_slice(&[127, 0, 0, 1]),
        }
        reply.extend_from_slice(&local_addr.port().to_be_bytes());
        socks_writer.write_all(&reply).await?;

        let udp_arc = Arc::new(udp_listener);
        let client_addr_arc = Arc::new(Mutex::new(None));

        {
            let mut pool = udp_pool.lock().await;
            pool.insert(conn_id, (udp_arc.clone(), client_addr_arc.clone()));
        }

        let tls_w = tls_writer.clone();
        let target_ref = target_key.clone();

        tokio::spawn(async move {
            let mut udp_buf = [0u8; 65535];
            loop {
                if let Ok((n, src)) = udp_arc.recv_from(&mut udp_buf).await {
                    *client_addr_arc.lock().await = Some(src);

                    if n > 10 {
                        let frag = udp_buf[2];
                        if frag != 0 {
                            continue;
                        }

                        let atyp = udp_buf[3];
                        let header_len = match atyp {
                            0x01 => 10, // IPv4
                            0x03 => 4 + 1 + udp_buf[4] as usize + 2, // Domain
                            0x04 => 22, // IPv6
                            _ => 10,
                        };

                        if n > header_len {
                            let payload = &udp_buf[header_len..n];
                            println!("[CLIENT TX] [{}] UDP Запрос от {} к '{}' | Data: {} bytes", conn_id, src, target_ref, payload.len());
                            let packet = build_packet(true, conn_id, &target_ref, payload);
                            if tls_w.lock().await.write_all(&packet).await.is_err() {
                                break;
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        });

        let mut dummy = [0u8; 1];
        let _ = socks_reader.read(&mut dummy).await;
        println!("[SOCKS UDP] [{}] Клиент закрыл UDP сессию ({})", conn_id, target_key);

        {
            let mut pool = udp_pool.lock().await;
            pool.remove(&conn_id);
        }
    }

    Ok(())
}

async fn read_socks_address<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    atype: u8,
) -> Result<String, DynError> {
    let mut buf = [0u8; 512];
    let host = match atype {
        0x01 => {
            reader.read_exact(&mut buf[..4]).await?;
            format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3])
        }
        0x03 => {
            reader.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            reader.read_exact(&mut buf[..len]).await?;
            String::from_utf8_lossy(&buf[..len]).to_string()
        }
        0x04 => {
            reader.read_exact(&mut buf[..16]).await?;
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&buf[..16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            format!("[{}]", ip)
        }
        _ => return Err("Неподдерживаемый ATYPE".into()),
    };

    reader.read_exact(&mut buf[..2]).await?;
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    Ok(format!("{}:{}", host, port))
}