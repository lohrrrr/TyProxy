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
    println!("[*] Запуск TLS TyProxy сервера на {}", cfg.bind_addr);

    let server_tun_tx: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(None));
    let clients_tun_broadcast: Arc<Mutex<Vec<mpsc::Sender<Vec<u8>>>>> =
    Arc::new(Mutex::new(Vec::new()));

    #[cfg(target_os = "linux")]
    if cfg.tun_enabled {
        let dev_result = {
            let tun_cfg = tokio_tun::TunBuilder::new();
            let tun_ip: std::net::Ipv4Addr = cfg.tun_ip.parse()?;
            let dest_ip: std::net::Ipv4Addr = "10.8.0.2".parse()?;
            tun_cfg
                .name(&cfg.tun_name)
                .tap(false)
                .packet_info(false)
                .address(tun_ip)
                .netmask(std::net::Ipv4Addr::new(255, 255, 255, 0))
                .destination(dest_ip)
                .up()
                .try_build()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        };

        match dev_result {
            Ok(dev) => {
                println!(
                    "[+] Создан TUN-интерфейс '{}' (IP: {})",
                         cfg.tun_name, cfg.tun_ip
                );
                setup_server_nat(&cfg.tun_name);
                let (mut tun_r, mut tun_w) = tokio::io::split(dev);
                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(2048);
                *server_tun_tx.lock().await = Some(tx);

                tokio::spawn(async move {
                    while let Some(pkt) = rx.recv().await {
                        let _ = tun_w.write_all(&pkt).await;
                    }
                });

                let b_clients = clients_tun_broadcast.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 65535];
                    loop {
                        if let Ok(n) = tun_r.read(&mut buf).await {
                            if n > 0 {
                                let pkt = buf[..n].to_vec();
                                let mut clients = b_clients.lock().await;
                                clients.retain(|c| !c.is_closed());
                                for c in clients.iter() {
                                    let _ = c.try_send(pkt.clone());
                                }
                            }
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("[-] Ошибка инициализации TUN (требуется root): {}", e);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    if cfg.tun_enabled {
        eprintln!("[-] TUN-режим сервера пока поддерживается только на Linux.");
    }

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor_clone = acceptor.clone();
        let s_tun_tx = server_tun_tx.clone();
        let b_clients = clients_tun_broadcast.clone();

        tokio::spawn(async move {
            match acceptor_clone.accept(stream).await {
                Ok(tls_stream) => {
                    println!("[+] TLS-подключение от {}", peer_addr);
                    let _ = handle_client(tls_stream, s_tun_tx, b_clients).await;
                }
                Err(e) => eprintln!("[-] TLS Handshake error: {}", e),
            }
        });
    }
}

async fn handle_client(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    server_tun_tx: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
    clients_tun_broadcast: Arc<Mutex<Vec<mpsc::Sender<Vec<u8>>>>>,
) -> Result<(), DynError> {
    let (mut reader, writer) = tokio::io::split(tls_stream);
    let writer_arc = Arc::new(Mutex::new(writer));
    let outbound_sockets: OutboundSocketsPool = Arc::new(Mutex::new(HashMap::new()));

    let (tun_client_tx, mut tun_client_rx) = mpsc::channel::<Vec<u8>>(1024);
    clients_tun_broadcast.lock().await.push(tun_client_tx);

    let writer_tun = writer_arc.clone();
    tokio::spawn(async move {
        while let Some(raw_ip_packet) = tun_client_rx.recv().await {
            let pkt = build_packet(2, 0, "", &raw_ip_packet);
            if writer_tun.lock().await.write_all(&pkt).await.is_err() {
                break;
            }
        }
    });

    loop {
        let mut len_buf = [0u8; 2];
        if reader.read_exact(&mut len_buf).await.is_err() {
            break;
        }

        let frame_len = u16::from_be_bytes(len_buf) as usize;
        let mut frame_buf = vec![0u8; frame_len];
        if reader.read_exact(&mut frame_buf).await.is_err() {
            break;
        }

        if let Some((pkt_type, conn_id, target_key, raw_payload)) = parse_client_frame(&frame_buf)
        {
            match pkt_type {
                0 => {
                    // TCP
                    let mut pool = outbound_sockets.lock().await;
                    if let Some(SocketTx::Tcp(tx)) = pool.get(&conn_id) {
                        if raw_payload.is_empty() {
                            pool.remove(&conn_id);
                        } else {
                            let _ = tx.send(raw_payload).await;
                        }
                    } else if !raw_payload.is_empty() {
                        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
                        pool.insert(conn_id, SocketTx::Tcp(tx));
                        let writer_ref = writer_arc.clone();
                        let key_ref = target_key.clone();
                        let pool_ref = outbound_sockets.clone();

                        tokio::spawn(async move {
                            let connect_result = timeout(Duration::from_secs(5), async {
                                let addrs = tokio::net::lookup_host(key_ref.trim()).await?;
                                if let Some(addr) = addrs.into_iter().next() {
                                    TcpStream::connect(addr).await
                                } else {
                                    Err(std::io::Error::new(
                                        std::io::ErrorKind::NotFound,
                                        "No IP",
                                    ))
                                }
                            })
                            .await;

                            if let Ok(Ok(outbound_stream)) = connect_result {
                                let (mut out_reader, mut out_writer) =
                                outbound_stream.into_split();
                                if out_writer.write_all(&raw_payload).await.is_ok() {
                                    let writer_tx = writer_ref.clone();
                                    let key_tx = key_ref.clone();

                                    tokio::spawn(async move {
                                        let mut buf = [0u8; 4096];
                                        loop {
                                            let n = match out_reader.read(&mut buf).await {
                                                Ok(0) | Err(_) => break,
                                                 Ok(n) => n,
                                            };
                                            let packet =
                                            build_packet(0, conn_id, &key_tx, &buf[..n]);
                                            if writer_tx.lock().await.write_all(&packet).await.is_err()
                                            {
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
                            }
                            pool_ref.lock().await.remove(&conn_id);
                        });
                    }
                }
                1 => {
                    // UDP
                    let pool = outbound_sockets.lock().await;
                    if !pool.contains_key(&conn_id) {
                        let target_key_clone = target_key.clone();
                        let writer_ref = writer_arc.clone();
                        let pool_ref = outbound_sockets.clone();

                        tokio::spawn(async move {
                            if let Ok(Ok(mut addrs)) = timeout(
                                Duration::from_secs(3),
                                                               tokio::net::lookup_host(target_key_clone.trim()),
                            )
                                .await
                                {
                                    if let Some(target_addr) = addrs.next() {
                                        if let Ok(udp_socket) = UdpSocket::bind("0.0.0.0:0").await {
                                            if udp_socket.connect(target_addr).await.is_ok() {
                                                let socket_arc = Arc::new(udp_socket);
                                                pool_ref.lock().await.insert(
                                                    conn_id,
                                                    SocketTx::Udp(socket_arc.clone()),
                                                );
                                                let _ = socket_arc.send(&raw_payload).await;

                                                let mut buf = [0u8; 65535];
                                                loop {
                                                    match socket_arc.recv(&mut buf).await {
                                                        Ok(n) => {
                                                            let packet = build_packet(
                                                                1,
                                                                conn_id,
                                                                &target_key_clone,
                                                                &buf[..n],
                                                            );
                                                            if writer_ref
                                                                .lock()
                                                                .await
                                                                .write_all(&packet)
                                                                .await
                                                                .is_err()
                                                                {
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
                    } else if let Some(SocketTx::Udp(sock)) = pool.get(&conn_id) {
                        let sock = sock.clone();
                        tokio::spawn(async move {
                            let _ = sock.send(&raw_payload).await;
                        });
                    }
                }
                2 => {
                    // Raw TUN IP-пакет
                    let lock = server_tun_tx.lock().await;
                    if let Some(tx) = &*lock {
                        let _ = tx.send(raw_payload).await;
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

fn parse_client_frame(data: &[u8]) -> Option<(u8, u64, String, Vec<u8>)> {
    if data.len() < 11 {
        return None;
    }
    let pkt_type = data[0];
    let conn_id = u64::from_be_bytes(data[1..9].try_into().ok()?);
    let meta_len = u16::from_be_bytes([data[9], data[10]]) as usize;
    if data.len() < 11 + meta_len {
        return None;
    }
    let raw_key = String::from_utf8_lossy(&data[11..11 + meta_len]).to_string();
    let payload = data[11 + meta_len..].to_vec();
    let mut target_key = raw_key
    .trim_matches(|c: char| c == '\0' || c.is_whitespace())
    .to_string();
    if !target_key.contains(':') && !target_key.is_empty() {
        target_key.push_str(":80");
    }
    Some((pkt_type, conn_id, target_key, payload))
}

#[cfg(target_os = "linux")]
fn setup_server_nat(tun_name: &str) {
    use std::process::Command;

    // 1. Enable IPv4 forwarding
    let forward_ok = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if forward_ok {
        println!("[+] IPv4 forwarding включен (net.ipv4.ip_forward=1)");
    } else {
        eprintln!("[!] Не удалось включить ip_forward автоматически. Выполните: sudo sysctl -w net.ipv4.ip_forward=1");
    }

    // 2. Configure iptables MASQUERADE
    let check_nat = Command::new("iptables")
        .args(["-t", "nat", "-C", "POSTROUTING", "-s", "10.8.0.0/24", "-j", "MASQUERADE"])
        .output();

    let nat_set = match check_nat {
        Ok(out) if out.status.success() => true,
        _ => {
            Command::new("iptables")
                .args(["-t", "nat", "-A", "POSTROUTING", "-s", "10.8.0.0/24", "-j", "MASQUERADE"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
    };

    // 3. Configure iptables FORWARD rules
    let check_fwd_in = Command::new("iptables")
        .args(["-C", "FORWARD", "-i", tun_name, "-j", "ACCEPT"])
        .output();
    if !matches!(check_fwd_in, Ok(out) if out.status.success()) {
        let _ = Command::new("iptables")
            .args(["-A", "FORWARD", "-i", tun_name, "-j", "ACCEPT"])
            .status();
    }

    let check_fwd_out = Command::new("iptables")
        .args(["-C", "FORWARD", "-o", tun_name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        .output();
    if !matches!(check_fwd_out, Ok(out) if out.status.success()) {
        let _ = Command::new("iptables")
            .args(["-A", "FORWARD", "-o", tun_name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
            .status();
    }

    if nat_set {
        println!("[+] Правила NAT (MASQUERADE) и FORWARD в iptables успешно настроены!");
    } else {
        eprintln!("[!] Не удалось автоматически настроить iptables MASQUERADE. Если трафик в туннеле не идет, выполните на сервере от root:");
        eprintln!("    sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j MASQUERADE");
        eprintln!("    sudo iptables -A FORWARD -i {} -j ACCEPT", tun_name);
        eprintln!("    sudo iptables -A FORWARD -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", tun_name);
    }
}
