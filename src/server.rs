use crate::config::ServerConfig;
use crate::crypto::{generate_self_signed_cert, DynError};

use rustls::ServerConfig as RustlsServerConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

enum SocketTx {
    Tcp(mpsc::Sender<Vec<u8>>),
    Udp(Arc<UdpSocket>),
}

type OutboundSocketsPool = Arc<Mutex<HashMap<u64, SocketTx>>>;

pub async fn run_server(cfg: ServerConfig) -> Result<(), DynError> {
    let (certs, key) = generate_self_signed_cert()?;
    let mut server_tls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    server_tls_config.alpn_protocols = vec![b"typroxy".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(server_tls_config));
    let listener = TcpListener::bind(&cfg.bind_addr).await?;
    println!("[*] Запущен TLS TyProxy Сервер на {}", cfg.bind_addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor_clone = acceptor.clone();

        tokio::spawn(async move {
            match acceptor_clone.accept(stream).await {
                Ok(tls_stream) => {
                    println!("[+] Установлено защищенное TLS-соединение с {}", peer_addr);
                    if let Err(e) = handle_client(tls_stream).await {
                        eprintln!("[-] Ошибка сессии клиента {}: {}", peer_addr, e);
                    }
                }
                Err(e) => eprintln!("[-] Ошибка TLS Handshake с {}: {}", peer_addr, e),
            }
        });
    }
}

async fn handle_client(tls_stream: tokio_rustls::server::TlsStream<TcpStream>) -> Result<(), DynError> {
    let (mut reader, writer) = tokio::io::split(tls_stream);
    let writer_arc = Arc::new(Mutex::new(writer));
    let outbound_sockets: OutboundSocketsPool = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let mut len_buf = [0u8; 2];
        if reader.read_exact(&mut len_buf).await.is_err() {
            println!("[*] Клиент завершил соединение с сервером.");
            break;
        }
        let frame_len = u16::from_be_bytes(len_buf) as usize;

        let mut frame_buf = vec![0u8; frame_len];
        if let Err(e) = reader.read_exact(&mut frame_buf).await {
            eprintln!("[-] Ошибка чтения тела фрейма от клиента: {}", e);
            break;
        }

        if let Some((is_udp, conn_id, target_key, raw_payload)) = parse_client_frame(&frame_buf) {
            let mut pool = outbound_sockets.lock().await;

            if !is_udp {
                // ==========================================
                //                TCP ЛОГИКА
                // ==========================================
                if let Some(SocketTx::Tcp(tx)) = pool.get(&conn_id) {
                    if raw_payload.is_empty() {
                        println!("[*] [{}] Клиент запросил закрытие TCP сокета для '{}'", conn_id, target_key);
                        pool.remove(&conn_id);
                    } else {
                        println!("[SERVER RX] [{}] TCP Запрос к '{}' | Data: {} bytes", conn_id, target_key, raw_payload.len());
                        let _ = tx.send(raw_payload).await;
                    }
                } else if !raw_payload.is_empty() {
                    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
                    pool.insert(conn_id, SocketTx::Tcp(tx));

                    let writer_ref = writer_arc.clone();
                    let key_ref = target_key.clone();
                    let pool_ref = outbound_sockets.clone();

                    tokio::spawn(async move {
                        println!("[DNS] [{}] Резолвинг хоста: '{}'", conn_id, key_ref);
                        
                        let connect_result = timeout(Duration::from_secs(5), async {
                            let addrs = tokio::net::lookup_host(key_ref.trim()).await?;
                            if let Some(addr) = addrs.into_iter().next() {
                                TcpStream::connect(addr).await
                            } else {
                                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No IP found"))
                            }
                        }).await;

                        match connect_result {
                            Ok(Ok(outbound_stream)) => {
                                println!("[+] [{}] TCP Соединение с {} установлено", conn_id, key_ref);
                                let (mut out_reader, mut out_writer) = outbound_stream.into_split();

                                if out_writer.write_all(&raw_payload).await.is_err() {
                                    pool_ref.lock().await.remove(&conn_id);
                                    return;
                                }

                                let writer_tx = writer_ref.clone();
                                let key_tx = key_ref.clone();

                                tokio::spawn(async move {
                                    let mut buf = [0u8; 4096];
                                    loop {
                                        let n = match out_reader.read(&mut buf).await {
                                            Ok(0) | Err(_) => break,
                                            Ok(n) => n,
                                        };

                                        println!("[SERVER TX] [{}] TCP Ответ для '{}' | Data: {} bytes", conn_id, key_tx, n);
                                        let packet = build_packet(false, conn_id, &key_tx, &buf[..n]);
                                        if writer_tx.lock().await.write_all(&packet).await.is_err() {
                                            break;
                                        }
                                    }
                                });

                                while let Some(data) = rx.recv().await {
                                    if out_writer.write_all(&data).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            _ => {
                                eprintln!("[-] [{}] Таймаут или ошибка подключения к '{}'", conn_id, key_ref);
                            }
                        }

                        pool_ref.lock().await.remove(&conn_id);
                    });
                }
            } else {
                // ==========================================
                //                UDP ЛОГИКА
                // ==========================================
                if !pool.contains_key(&conn_id) {
                    let target_key_clone = target_key.clone();
                    let writer_ref = writer_arc.clone();
                    let pool_ref = outbound_sockets.clone();

                    tokio::spawn(async move {
                        let res = timeout(Duration::from_secs(3), tokio::net::lookup_host(target_key_clone.trim())).await;
                        
                        if let Ok(Ok(mut addrs)) = res {
                            if let Some(target_addr) = addrs.next() {
                                if let Ok(udp_socket) = UdpSocket::bind("0.0.0.0:0").await {
                                    if udp_socket.connect(target_addr).await.is_ok() {
                                        println!("[+] [{}] UDP Сокет связан с {}", conn_id, target_addr);
                                        let socket_arc = Arc::new(udp_socket);
                                        
                                        pool_ref.lock().await.insert(conn_id, SocketTx::Udp(socket_arc.clone()));

                                        let recv_socket = socket_arc.clone();
                                        let key_ref = target_key_clone.clone();

                                        let _ = recv_socket.send(&raw_payload).await;

                                        let mut buf = [0u8; 65535];
                                        loop {
                                            match recv_socket.recv(&mut buf).await {
                                                Ok(n) => {
                                                    println!("[SERVER TX] [{}] UDP Ответ от {} | Data: {} bytes", conn_id, key_ref, n);
                                                    let packet = build_packet(true, conn_id, &key_ref, &buf[..n]);
                                                    if writer_ref.lock().await.write_all(&packet).await.is_err() {
                                                        break;
                                                    }
                                                }
                                                Err(_) => break,
                                            }
                                        }

                                        pool_ref.lock().await.remove(&conn_id);
                                    }
                                }
                            }
                        }
                    });
                } else if let Some(SocketTx::Udp(socket_arc)) = pool.get(&conn_id) {
                    println!("[SERVER RX] [{}] UDP Отправка пакета на '{}' | Data: {} bytes", conn_id, target_key, raw_payload.len());
                    let sock = socket_arc.clone();
                    let payload = raw_payload.clone();
                    tokio::spawn(async move {
                        let _ = sock.send(&payload).await;
                    });
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

fn parse_client_frame(data: &[u8]) -> Option<(bool, u64, String, Vec<u8>)> {
    if data.len() < 11 {
        return None;
    }

    let is_udp = data[0] == 1;
    let conn_id = u64::from_be_bytes(data[1..9].try_into().ok()?);
    let meta_len = u16::from_be_bytes([data[9], data[10]]) as usize;

    if data.len() < 11 + meta_len {
        return None;
    }

    let raw_key = String::from_utf8_lossy(&data[11..11 + meta_len]).to_string();
    let payload = data[11 + meta_len..].to_vec();

    let mut target_key = raw_key.trim_matches(|c: char| c == '\0' || c.is_whitespace()).to_string();
    if !target_key.contains(':') && !target_key.is_empty() {
        target_key.push_str(":80");
    }

    Some((is_udp, conn_id, target_key, payload))
}