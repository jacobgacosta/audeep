use crate::scanner::{self, PortResult};
use crate::vuln::Finding;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

#[derive(Debug, Clone, Serialize)]
pub struct HostInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub is_alive: bool,
    pub open_ports: Vec<PortResult>,
    pub latency_ms: Option<u128>,
    #[serde(default)]
    pub vulnerabilities: Vec<Finding>,
}

static OUI_JSON: &str = include_str!("../assets/oui.json");

fn oui_db() -> HashMap<String, String> {
    serde_json::from_str::<HashMap<String, String>>(OUI_JSON).unwrap_or_default()
}

pub fn lookup_vendor(mac: &str) -> Option<String> {
    let clean = mac.to_uppercase().replace('-', ":");
    let prefix = clean.split(':').take(3).collect::<Vec<_>>().join(":");
    if prefix.len() != 8 {
        return None;
    }
    // La DB tiene claves en formato XX:XX:XX ya en mayúsculas
    let db = oui_db();
    db.get(&prefix).cloned().or_else(|| {
        // fallback a búsqueda case-insensitive para DB antigua
        db.iter()
            .find(|(k, _)| k.to_uppercase() == prefix)
            .map(|(_, v)| v.clone())
    })
}

fn get_local_ipv4() -> Option<Ipv4Addr> {
    // truco UDP para descubrir IP local sin enviar tráfico real
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // no necesita ser alcanzable, solo para que el SO elija interfaz
    let _ = socket.connect("8.8.8.8:80");
    let addr = socket.local_addr().ok()?;
    match addr.ip() {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() || v4.is_loopback() {
                None
            } else {
                Some(v4)
            }
        }
        _ => None,
    }
}

pub fn local_subnet_cidr() -> Option<String> {
    // Asumimos /24 por simplicidad; en versión completa se leería máscara real via `if-addrs`
    get_local_ipv4().map(|ip| {
        let octets = ip.octets();
        format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
    })
}

pub fn hosts_in_subnet(ip: Ipv4Addr, prefix_len: u8) -> Vec<Ipv4Addr> {
    // Solo soportamos /24 por ahora (caso hogareño común). Para otros prefijos se podría ampliar.
    if prefix_len != 24 {
        // fallback a /24
        let base = Ipv4Addr::new(ip.octets()[0], ip.octets()[1], ip.octets()[2], 0);
        return (1..254).map(|i| Ipv4Addr::new(base.octets()[0], base.octets()[1], base.octets()[2], i)).collect();
    }
    let base = Ipv4Addr::new(ip.octets()[0], ip.octets()[1], ip.octets()[2], 0);
    (1..254).map(|i| Ipv4Addr::new(base.octets()[0], base.octets()[1], base.octets()[2], i)).collect()
}

async fn is_host_alive(ip: IpAddr, timeout_ms: u64) -> (bool, Option<u128>) {
    let start = std::time::Instant::now();
    // Heurística rápida: intentar 80,445,22,53 con timeout corto. Si alguno abre, está vivo.
    let ports = [80, 445, 22, 53];
    for &port in &ports {
        let res = scanner::scan_port(ip, port, timeout_ms).await;
        if res.state == "open" {
            return (true, Some(start.elapsed().as_millis()));
        }
    }
    // Fallback ICMP ping via comando del sistema (no requiere raw sockets si hay binario ping)
    if ping_host(ip, timeout_ms).await {
        return (true, Some(start.elapsed().as_millis()));
    }
    (false, None)
}

async fn ping_host(ip: IpAddr, timeout_ms: u64) -> bool {
    let ip_str = ip.to_string();
    // Windows: ping -n 1 -w <ms>  | Unix: ping -c 1 -W <sec>
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let timeout_arg = format!("{}", timeout_ms);
        let mut c = tokio::process::Command::new("ping");
        c.args(["-n", "1", "-w", &timeout_arg, &ip_str]);
        c
    };
    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let secs = ((timeout_ms + 999) / 1000).to_string();
        let mut c = tokio::process::Command::new("ping");
        c.args(["-c", "1", "-W", &secs, &ip_str]);
        c
    };

    // Evitar colgarse: timeout global 1.5x
    let res = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms + 500),
        cmd.output(),
    )
    .await;

    match res {
        Ok(Ok(out)) => out.status.success(),
        _ => false,
    }
}

pub async fn discover_hosts(timeout_ms: u64, max_concurrency: usize) -> Vec<HostInfo> {
    let local_ip = match get_local_ipv4() {
        Some(ip) => ip,
        None => return Vec::new(),
    };

    let candidates = hosts_in_subnet(local_ip, 24);

    // limitar concurrencia con semáforo
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrency));
    let mut tasks = Vec::new();

    for ip in candidates {
        // no escanearnos a nosotros mismos de forma redundante, pero lo incluimos al final como host local
        if ip == local_ip {
            continue;
        }
        let sem = semaphore.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let (alive, latency) = is_host_alive(IpAddr::V4(ip), timeout_ms).await;
            if alive {
                // para hosts vivos, hacer escaneo rápido de puertos comunes
                let open_ports = scanner::scan_common_ports(IpAddr::V4(ip), timeout_ms).await;
                let vulnerabilities = crate::vuln::check_host(&open_ports);
                HostInfo {
                    ip: ip.to_string(),
                    hostname: None,
                    mac: None,
                    vendor: None,
                    is_alive: true,
                    open_ports,
                    latency_ms: latency,
                    vulnerabilities,
                }
            } else {
                HostInfo {
                    ip: ip.to_string(),
                    hostname: None,
                    mac: None,
                    vendor: None,
                    is_alive: false,
                    open_ports: Vec::new(),
                    latency_ms: latency,
                    vulnerabilities: Vec::new(),
                }
            }
        }));
    }

    let mut alive_hosts = Vec::new();
    for t in tasks {
        if let Ok(host) = t.await {
            if host.is_alive {
                alive_hosts.push(host);
            }
        }
    }

    // Añadir host local al inicio
    let local_open = scanner::scan_common_ports(IpAddr::V4(local_ip), timeout_ms).await;
    let local_vulns = crate::vuln::check_host(&local_open);
    alive_hosts.insert(
        0,
        HostInfo {
            ip: local_ip.to_string(),
            hostname: hostname::get().ok().and_then(|h| h.into_string().ok()),
            mac: None,
            vendor: None,
            is_alive: true,
            open_ports: local_open,
            latency_ms: Some(0),
            vulnerabilities: local_vulns,
        },
    );

    alive_hosts.sort_by(|a, b| a.ip.cmp(&b.ip));
    alive_hosts
}

// Helper para resolver MAC via tabla ARP (solo lectura, sin raw sockets)
// En Windows: `arp -a`, en Linux: `/proc/net/arp`
pub fn arp_table_snapshot() -> HashMap<String, String> {
    let mut map = HashMap::new();
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("arp").arg("-a").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                // Formato típico:  192.168.1.1           00-11-22-33-44-55     dinámico
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let ip = parts[0];
                    let mac = parts[1];
                    if ip.parse::<IpAddr>().is_ok() && mac.contains('-') || mac.contains(':') {
                        map.insert(ip.to_string(), mac.to_string());
                    }
                }
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let ip = parts[0];
                    let mac = parts[3];
                    if mac != "00:00:00:00:00:00" {
                        map.insert(ip.to_string(), mac.to_string());
                    }
                }
            }
        }
    }
    map
}

pub fn enrich_with_arp(mut hosts: Vec<HostInfo>) -> Vec<HostInfo> {
    let arp = arp_table_snapshot();
    for h in &mut hosts {
        if let Some(mac) = arp.get(&h.ip) {
            h.mac = Some(mac.clone());
            h.vendor = lookup_vendor(mac);
        }
    }
    // Merge: añadir hosts que están en ARP pero no fueron detectados como vivos por TCP/ping
    // (ej. dispositivos silenciosos que no exponen puertos 80/445 pero sí responden ARP)
    let alive_ips: std::collections::HashSet<String> = hosts.iter().map(|h| h.ip.clone()).collect();
    for (ip, mac) in arp.iter() {
        // filtrar solo IPs de la misma subred y no multicast/broadcast
        if alive_ips.contains(ip) {
            continue;
        }
        if ip.parse::<IpAddr>().is_err() {
            continue;
        }
        // Evitar multicast, broadcast y network
        if ip.starts_with("224.") || ip.starts_with("239.") || ip == "0.0.0.0" {
            continue;
        }
        // Filtrar .0 (network) y .255 (broadcast) de la subred local
        if ip.ends_with(".0") || ip.ends_with(".255") {
            continue;
        }
        // Solo añadir si pertenece a la subred local aproximada (/24 del host)
        if let Some(local) = get_local_ipv4() {
            let local_oct = local.octets();
            if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
                let oct = parsed.octets();
                if oct[0] != local_oct[0] || oct[1] != local_oct[1] || oct[2] != local_oct[2] {
                    continue;
                }
            }
        }
        let vendor = lookup_vendor(mac);
        hosts.push(HostInfo {
            ip: ip.clone(),
            hostname: None,
            mac: Some(mac.clone()),
            vendor,
            is_alive: true,
            open_ports: Vec::new(),
            latency_ms: None,
            vulnerabilities: Vec::new(),
        });
    }
    hosts.sort_by(|a, b| a.ip.cmp(&b.ip));
    hosts
}
