use crate::probe;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
    8080, 8443,
];

/// Resultado de un sondeo TCP individual.
///
/// La distinción importante es entre `Refused` y `Filtered`: un RST prueba que
/// hay una pila TCP viva en esa IP, un timeout no prueba nada. El código viejo
/// metía ambos en "closed", así que un host que rechaza el puerto se perdía.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Handshake completado: hay un servicio escuchando.
    Open,
    /// El host respondió RST: puerto cerrado, **host vivo**.
    Refused,
    /// Silencio (timeout, filtrado o inalcanzable): no se puede afirmar nada.
    Filtered,
}

impl Probe {
    pub fn is_open(self) -> bool {
        matches!(self, Probe::Open)
    }

    /// Estado textual histórico del reporte ("open" | "closed").
    pub fn as_state(self) -> &'static str {
        if self.is_open() { "open" } else { "closed" }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub state: String, // "open" | "closed"
    pub banner: Option<String>,
    pub service_hint: Option<String>,
}

/// Puertos cuyo servicio saluda primero (banner pasivo).
///
/// No incluye 80/443/8080: ahí el servidor espera la petición, así que leer
/// solo quema el timeout completo por host sin traer nada.
pub const BANNER_PORTS: &[u16] = &[21, 22, 23, 25, 110, 143, 993, 995, 3306, 5432, 5900];

pub fn should_grab_banner(port: u16) -> bool {
    BANNER_PORTS.contains(&port)
}

/// `true` si el error del connect implica que el host contestó (RST).
///
/// No alcanza con mirar `ErrorKind`: en Windows tokio puede devolver el código
/// Winsock crudo sin mapear, así que se aceptan también WSAECONNREFUSED (10061)
/// y WSAECONNRESET (10054). Un timeout (10060) o host inalcanzable (10065) NO
/// cuentan: no son prueba de vida.
pub fn is_refused(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(
        e.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
    ) {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        const WSAECONNREFUSED: i32 = 10061;
        const WSAECONNRESET: i32 = 10054;
        if matches!(
            e.raw_os_error(),
            Some(WSAECONNREFUSED) | Some(WSAECONNRESET)
        ) {
            return true;
        }
    }
    false
}

pub fn service_hint(port: u16) -> Option<String> {
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

/// En el 445 el "banner" es el dialecto SMB negociado: esa es la diferencia
/// entre "hay un SMB" y "hay un SMB que todavia acepta SMBv1".
async fn smb_dialect_banner(ip: IpAddr, timeout_ms: u64) -> Option<String> {
    match probe::smb1_enabled(ip, timeout_ms).await {
        Some(true) => Some("SMB1 habilitado".to_string()),
        Some(false) => Some("SMB2/3".to_string()),
        None => None,
    }
}

async fn grab_banner(stream: &mut TcpStream, banner_ms: u64) -> Option<String> {
    let mut buf = vec![0u8; 1024];
    match timeout(Duration::from_millis(banner_ms), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let raw = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            if raw.is_empty() {
                None
            } else {
                // limitar a 200 chars para no ensuciar el reporte
                Some(raw.chars().take(200).collect())
            }
        }
        _ => None,
    }
}

/// Sondea un puerto con timeouts explícitos (conexión y banner).
pub async fn probe_port_with(
    ip: IpAddr,
    port: u16,
    timeout_ms: u64,
    banner_ms: u64,
) -> (Probe, Option<String>) {
    let addr = SocketAddr::new(ip, port);
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let banner = if should_grab_banner(port) {
                grab_banner(&mut stream, banner_ms).await
            } else {
                None
            };
            (Probe::Open, banner)
        }
        Ok(Err(e)) if is_refused(&e) => (Probe::Refused, None),
        _ => (Probe::Filtered, None),
    }
}

/// Sondeo estándar: 800 ms de ventana para el banner.
pub async fn probe_port(ip: IpAddr, port: u16, timeout_ms: u64) -> (Probe, Option<String>) {
    probe_port_with(ip, port, timeout_ms, 800).await
}

/// Sondeo con estado textual, compatible con el reporte histórico.
pub async fn scan_port(ip: IpAddr, port: u16, timeout_ms: u64) -> PortResult {
    let (probe, banner) = probe_port(ip, port, timeout_ms).await;
    PortResult {
        port,
        state: probe.as_state().to_string(),
        banner,
        service_hint: service_hint(port),
    }
}

/// Escanea lista de puertos concurrentemente para un IP dado.
/// Retorna solo puertos abiertos, ordenados.
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
    // Confirmacion activa del 445: se negocia SMB1 en lugar de suponerlo.
    for res in opens.iter_mut() {
        if res.port == 445 && res.banner.is_none() {
            res.banner = smb_dialect_banner(ip, timeout_ms).await;
        }
    }
    opens
}

/// Escanea todos los COMMON_PORTS
pub async fn scan_common_ports(ip: IpAddr, timeout_ms: u64) -> Vec<PortResult> {
    scan_target(ip, COMMON_PORTS, timeout_ms).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_errors_count_as_host_alive() {
        assert!(is_refused(&std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused"
        )));
        assert!(is_refused(&std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset"
        )));
        // Los que no prueban nada
        assert!(!is_refused(&std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout"
        )));
        assert!(!is_refused(&std::io::Error::new(
            std::io::ErrorKind::Other,
            "otro"
        )));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn winsock_codes_are_understood() {
        const WSAECONNREFUSED: i32 = 10061;
        const WSAECONNRESET: i32 = 10054;
        const WSAETIMEDOUT: i32 = 10060;
        const WSAEHOSTUNREACH: i32 = 10065;
        assert!(is_refused(&std::io::Error::from_raw_os_error(
            WSAECONNREFUSED
        )));
        assert!(is_refused(&std::io::Error::from_raw_os_error(
            WSAECONNRESET
        )));
        assert!(!is_refused(&std::io::Error::from_raw_os_error(
            WSAETIMEDOUT
        )));
        assert!(!is_refused(&std::io::Error::from_raw_os_error(
            WSAEHOSTUNREACH
        )));
    }

    #[tokio::test]
    async fn closed_loopback_port_is_never_open() {
        let (probe, _) = probe_port("127.0.0.1".parse().unwrap(), 54321, 500).await;
        assert!(!probe.is_open(), "un puerto cerrado nunca es Open");
        assert_eq!(probe.as_state(), "closed");
        assert!(matches!(probe, Probe::Refused | Probe::Filtered));
    }

    #[tokio::test]
    async fn listener_is_open() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (probe, _) = probe_port("127.0.0.1".parse().unwrap(), port, 500).await;
        assert_eq!(probe, Probe::Open);
        assert!(probe.is_open());
        assert_eq!(probe.as_state(), "open");
    }

    #[test]
    fn banner_only_for_talkative_services() {
        assert!(should_grab_banner(22));
        assert!(should_grab_banner(21));
        assert!(!should_grab_banner(80), "HTTP espera la peticion");
        assert!(!should_grab_banner(445), "445 se confirma con el probe SMB");
        assert!(!should_grab_banner(3389));
    }

    #[test]
    fn service_hints_known() {
        assert_eq!(service_hint(445).as_deref(), Some("SMB"));
        assert_eq!(service_hint(22).as_deref(), Some("SSH"));
        assert_eq!(service_hint(9999), None);
    }

    #[tokio::test]
    async fn scan_target_only_returns_open_sorted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();
        let ports = [54321u16, open_port];
        let res = scan_target("127.0.0.1".parse().unwrap(), &ports, 400).await;
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].port, open_port);
        assert_eq!(res[0].state, "open");
    }
}
