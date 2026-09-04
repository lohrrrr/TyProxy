use crate::crypto::DynError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;

pub type ClientSocketsPool = Arc<Mutex<HashMap<u64, tokio::net::tcp::OwnedWriteHalf>>>;
pub type UdpRelayPool = Arc<Mutex<HashMap<u64, (Arc<UdpSocket>, Arc<Mutex<Option<SocketAddr>>>)>>>;
pub type TlsWriterArc = Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>;

static CONN_COUNTER: AtomicU64 = AtomicU64::new(1);

pub async fn run_socks5_module(
    socks_bind: String,
    writer_arc: TlsWriterArc,
    active_socks: ClientSocketsPool,
    udp_relays: UdpRelayPool,
) -> Result<(), DynError> {
    let listener = match TcpListener::bind(&socks_bind).await {
        Ok(l) => {
            println!("[+] Модуль SOCKS5 запущен на {}", socks_bind);
            l
        }
        Err(e) => {
            eprintln!("[-] Ошибка привязки SOCKS5 к {}: {}", socks_bind, e);
            return Err(e.into());
        }
    };

    loop {
        if let Ok((socks_stream, peer_addr)) = listener.accept().await {
            let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed);
            println!("[SOCKS] [{}] Новое подключение от {}", conn_id, peer_addr);
            let w_ref = writer_arc.clone();
            let p_ref = active_socks.clone();
            let u_ref = udp_relays.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_socks_connection(conn_id, socks_stream, w_ref, p_ref, u_ref).await
                {
                    eprintln!("[-] [{}] Ошибка SOCKS-сессии: {}", conn_id, e);
                }
            });
        }
    }
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
        // TCP CONNECT
        let target_key = read_socks_address(&mut socks_reader, buf[3]).await?;
        socks_writer
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

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

            let packet = crate::client::build_packet(0, conn_id, &target_key, &payload_buf[..n]);
            if tls_writer.lock().await.write_all(&packet).await.is_err() {
                break;
            }
        }

        let close_packet = crate::client::build_packet(0, conn_id, &target_key, &[]);
        let _ = tls_writer.lock().await.write_all(&close_packet).await;

        let mut pool = socks_pool.lock().await;
        pool.remove(&conn_id);
    } else if cmd == 0x03 {
        // UDP ASSOCIATE
        let target_key = read_socks_address(&mut socks_reader, buf[3]).await?;
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
                            0x01 => 10,
                            0x03 => 4 + 1 + udp_buf[4] as usize + 2,
                            0x04 => 22,
                            _ => 10,
                        };

                        if n > header_len {
                            let payload = &udp_buf[header_len..n];
                            let packet =
                                crate::client::build_packet(1, conn_id, &target_ref, payload);
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

        let mut pool = udp_pool.lock().await;
        pool.remove(&conn_id);
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
