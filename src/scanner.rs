use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080,
    8443,
];

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub state: String, // "open" | "closed"
    pub banner: Option<String>,
    pub service_hint: Option<String>,
}

fn service_hint(port: u16) -> Option<String> {
    let hint = match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "MSRPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        1723 => "PPTP",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt",
        _ => return None,
    };
    Some(hint.to_string())
}

pub async fn scan_port(ip: IpAddr, port: u16, timeout_ms: u64) -> PortResult {
    let addr = SocketAddr::new(ip, port);
    let conn_timeout = Duration::from_millis(timeout_ms);

    match timeout(conn_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            // intentar banner grab con timeout corto
            let mut buf = vec![0u8; 1024];
            let banner = match timeout(Duration::from_millis(800), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let raw = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    if raw.is_empty() {
                        None
                    } else {
                        // limitar a 200 chars para no ensuciar reporte
                        Some(raw.chars().take(200).collect())
                    }
                }
                _ => None,
            };

            PortResult {
                port,
                state: "open".to_string(),
                banner,
                service_hint: service_hint(port),
            }
        }
        _ => PortResult {
            port,
            state: "closed".to_string(),
            banner: None,
            service_hint: service_hint(port),
        },
    }
}

/// Escanea lista de puertos concurrentemente para un IP dado
/// Retorna solo puertos abiertos
pub async fn scan_target(ip: IpAddr, ports: &[u16], timeout_ms: u64) -> Vec<PortResult> {
    let mut tasks = Vec::new();
    for &port in ports {
        tasks.push(tokio::spawn(scan_port(ip, port, timeout_ms)));
    }

    let mut opens = Vec::new();
    for t in tasks {
        if let Ok(res) = t.await {
            if res.state == "open" {
                opens.push(res);
            }
        }
    }
    opens.sort_by_key(|r| r.port);
    opens
}

/// Escanea todos los COMMON_PORTS
pub async fn scan_common_ports(ip: IpAddr, timeout_ms: u64) -> Vec<PortResult> {
    scan_target(ip, COMMON_PORTS, timeout_ms).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_scan_loopback_closed() {
        // Puerto alto improbable abierto
        let res = scan_port("127.0.0.1".parse().unwrap(), 54321, 200).await;
        assert_eq!(res.state, "closed");
    }
}
