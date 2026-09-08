use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

#[cfg(target_os = "linux")]
use tokio_tun::{Tun, TunBuilder};

use crate::config::ClientConfig;
use crate::modules::socks5::TlsWriterArc;

pub type TunWriterArc = Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>;

#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(target_os = "linux")]
    #[error("TUN error: {0}")]
    Tun(#[from] tokio_tun::Error),
    #[error("DNS resolution error: {0}")]
    Dns(String),
    #[error("Default gateway not found")]
    GatewayNotFound,
    #[error("Command execution failed: {0}")]
    CommandFailed(String),
    #[error("TUN interface is only supported on Linux")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone)]
pub struct RouteInfo {
    pub gateway: Option<Ipv4Addr>,
    pub interface: String,
}

/// Restores original routing table state upon tunnel termination.
pub struct RouteGuard {
    tun_name: String,
    server_ip: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    interface: String,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("ip")
            .args(["route", "del", "0.0.0.0/1", "dev", &self.tun_name])
            .status();
            let _ = Command::new("ip")
            .args(["route", "del", "128.0.0.0/1", "dev", &self.tun_name])
            .status();
            if let Some(gw) = self.gateway {
                let _ = Command::new("ip")
                .args([
                    "route",
                    "del",
                    &self.server_ip.to_string(),
                      "via",
                      &gw.to_string(),
                ])
                .status();
            } else {
                let _ = Command::new("ip")
                .args([
                    "route",
                    "del",
                    &self.server_ip.to_string(),
                      "dev",
                      &self.interface,
                ])
                .status();
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(gw) = self.gateway {
                let _ = Command::new("route")
                .args(["delete", "0.0.0.0", "mask", "128.0.0.0", &gw.to_string()])
                .status();
                let _ = Command::new("route")
                .args(["delete", "128.0.0.0", "mask", "128.0.0.0", &gw.to_string()])
                .status();
                let _ = Command::new("route")
                .args([
                    "delete",
                    &self.server_ip.to_string(),
                      "mask",
                      "255.255.255.255",
                      &gw.to_string(),
                ])
                .status();
            }
        }
    }
}

#[allow(dead_code)]
pub struct TunDevice {
    #[cfg(target_os = "linux")]
    pub tun: Tun,
    pub guard: RouteGuard,
}

impl TunDevice {
    #[cfg(target_os = "linux")]
    pub async fn create(
        tun_name: &str,
        tun_ip: Ipv4Addr,
        tun_netmask: Ipv4Addr,
        server_host: &str,
    ) -> Result<Self, TunError> {
        let server_ip = resolve_ipv4(server_host)?;
        let tun = TunBuilder::new()
        .name(tun_name)
        .tap(false)
        .packet_info(false)
        .address(tun_ip)
        .netmask(tun_netmask)
        .up()
        .try_build()
        .map_err(TunError::Tun)?;

        let actual_name = tun.name().to_string();
        let default_route = get_default_route()?;
        setup_routes(&actual_name, server_ip, &default_route)?;

        let guard = RouteGuard {
            tun_name: actual_name,
            server_ip,
            gateway: default_route.gateway,
            interface: default_route.interface,
        };

        Ok(Self { tun, guard })
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn create(
        _tun_name: &str,
        _tun_ip: Ipv4Addr,
        _tun_netmask: Ipv4Addr,
        _server_host: &str,
    ) -> Result<Self, TunError> {
        Err(TunError::UnsupportedPlatform)
    }
}

pub async fn run_tun_module(
    cfg: ClientConfig,
    tls_writer: TlsWriterArc,
    tun_slot: TunWriterArc,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "linux")]
    {
        let tun_ip: Ipv4Addr = cfg.tun_ip.parse()?;
        let netmask: Ipv4Addr = "255.255.255.0".parse()?;
        let tun_dev = TunDevice::create(&cfg.tun_name, tun_ip, netmask, &cfg.server_host).await?;

        let (mut reader, mut writer) = tokio::io::split(tun_dev.tun);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        *tun_slot.lock().await = Some(tx);

        let writer_tls = tls_writer.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                     Ok(n) => {
                         let packet = crate::client::build_packet(2, 0, "", &buf[..n]);
                         if writer_tls.lock().await.write_all(&packet).await.is_err() {
                             break;
                         }
                     }
                }
            }
        });

        while let Some(pkt) = rx.recv().await {
            if writer.write_all(&pkt).await.is_err() {
                break;
            }
        }

        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cfg, tls_writer, tun_slot);
        Err(Box::new(TunError::UnsupportedPlatform))
    }
}

#[allow(dead_code)]
fn resolve_ipv4(server_host: &str) -> Result<Ipv4Addr, TunError> {
    let host = if let Some(idx) = server_host.rfind(':') {
        if !server_host.starts_with('[') {
            &server_host[..idx]
        } else {
            server_host
        }
    } else {
        server_host
    };

    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }

    let socket_str = format!("{}:80", host);
    let addrs: Vec<SocketAddr> = socket_str
    .to_socket_addrs()
    .map_err(|e| TunError::Dns(format!("{}: {}", host, e)))?
    .collect();

    for addr in addrs {
        if let IpAddr::V4(v4) = addr.ip() {
            return Ok(v4);
        }
    }

    Err(TunError::Dns(format!("No IPv4 address found for {}", host)))
}

#[cfg(target_os = "linux")]
pub fn get_default_route() -> Result<RouteInfo, TunError> {
    let output = Command::new("ip")
    .args(["-4", "route", "show", "default"])
    .output()
    .map_err(TunError::Io)?;

    if !output.status.success() {
        return Err(TunError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first() != Some(&"default") {
            continue;
        }

        let mut gateway = None;
        let mut interface = None;
        let mut i = 1;

        while i < tokens.len() {
            if tokens[i] == "via" && i + 1 < tokens.len() {
                if let Ok(ip) = tokens[i + 1].parse::<Ipv4Addr>() {
                    gateway = Some(ip);
                }
                i += 2;
            } else if tokens[i] == "dev" && i + 1 < tokens.len() {
                interface = Some(tokens[i + 1].to_string());
                i += 2;
            } else {
                i += 1;
            }
        }

        if let Some(iface) = interface {
            return Ok(RouteInfo {
                gateway,
                interface: iface,
            });
        }
    }

    Err(TunError::GatewayNotFound)
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub fn get_default_route() -> Result<RouteInfo, TunError> {
    let output = Command::new("route")
    .args(["print", "0.0.0.0"])
    .output()
    .map_err(TunError::Io)?;

    if !output.status.success() {
        return Err(TunError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() >= 5 && tokens[0] == "0.0.0.0" && tokens[1] == "0.0.0.0" {
            if let Ok(gw) = tokens[2].parse::<Ipv4Addr>() {
                return Ok(RouteInfo {
                    gateway: Some(gw),
                          interface: tokens[3].to_string(),
                });
            }
        }
    }

    Err(TunError::GatewayNotFound)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn get_default_route() -> Result<RouteInfo, TunError> {
    Err(TunError::GatewayNotFound)
}

#[cfg(target_os = "linux")]
fn setup_routes(
    tun_name: &str,
    server_ip: Ipv4Addr,
    route_info: &RouteInfo,
) -> Result<(), TunError> {
    if let Some(gw) = route_info.gateway {
        let _ = Command::new("ip")
        .args([
            "route",
            "add",
            &server_ip.to_string(),
              "via",
              &gw.to_string(),
        ])
        .status();
    } else {
        let _ = Command::new("ip")
        .args([
            "route",
            "add",
            &server_ip.to_string(),
              "dev",
              &route_info.interface,
        ])
        .status();
    }

    run_cmd("ip", &["route", "add", "0.0.0.0/1", "dev", tun_name])?;
    run_cmd("ip", &["route", "add", "128.0.0.0/1", "dev", tun_name])?;

    let _ = Command::new("sysctl")
    .args(["-w", &format!("net.ipv4.conf.{}.rp_filter=2", tun_name)])
    .status();

    Ok(())
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn setup_routes(
    _tun_name: &str,
    server_ip: Ipv4Addr,
    route_info: &RouteInfo,
) -> Result<(), TunError> {
    if let Some(gw) = route_info.gateway {
        run_cmd(
            "route",
            &[
                "add",
                &server_ip.to_string(),
                "mask",
                "255.255.255.255",
                &gw.to_string(),
            ],
        )?;
        run_cmd(
            "route",
            &["add", "0.0.0.0", "mask", "128.0.0.0", &gw.to_string()],
        )?;
        run_cmd(
            "route",
            &["add", "128.0.0.0", "mask", "128.0.0.0", &gw.to_string()],
        )?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn setup_routes(
    _tun_name: &str,
    _server_ip: Ipv4Addr,
    _route_info: &RouteInfo,
) -> Result<(), TunError> {
    Ok(())
}

#[allow(dead_code)]
fn run_cmd(program: &str, args: &[&str]) -> Result<(), TunError> {
    let output = Command::new(program)
    .args(args)
    .output()
    .map_err(TunError::Io)?;

    if !output.status.success() {
        return Err(TunError::CommandFailed(format!(
            "{} {}: {}",
            program,
            args.join(" "),
                                                   String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}
