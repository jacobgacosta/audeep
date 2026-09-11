use crate::scanner::{self, PortResult};
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
}

// Base de datos OUI mínima embebida (muestra). Para producción usar base completa IEEE.
fn oui_db() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("54:14:F3", "AzureWave / Realtek (common WiFi)");
    m.insert("00:15:5D", "Microsoft (Hyper-V)");
    m.insert("00:50:56", "VMware");
    m.insert("0A:00:27", "VirtualBox");
    m.insert("3C:22:FB", "Apple");
    m.insert("F4:5C:89", "Apple");
    m.insert("FC:FB:FB", "Apple");
    m.insert("A4:5E:60", "Apple");
    m.insert("B8:27:EB", "Raspberry Pi Foundation");
    m.insert("D8:3A:DD", "Raspberry Pi");
    m.insert("DC:A6:32", "Raspberry Pi");
    m.insert("E4:5F:01", "Raspberry Pi");
    m.insert("2C:CF:67", "Espressif (ESP32)");
    m.insert("24:6F:28", "Espressif");
    m.insert("30:AE:A4", "Espressif");
    m.insert("84:CC:A8", "Espressif");
    m.insert("48:27:E2", "Xiaomi");
    m.insert("64:CC:2E", "Xiaomi");
    m.insert("7C:2F:80", "Xiaomi");
    m.insert("00:1A:11", "Google");
    m.insert("F4:F5:D8", "Google Nest");
    m.insert("18:B4:30", "Nest Labs");
    m
}

pub fn lookup_vendor(mac: &str) -> Option<String> {
    let clean = mac.to_uppercase().replace('-', ":");
    let prefix = clean.split(':').take(3).collect::<Vec<_>>().join(":");
    if prefix.len() != 8 {
        return None;
    }
    oui_db().get(prefix.as_str()).map(|v| v.to_string())
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
    // Heurística rápida: intentar 80 y 445 con timeout corto. Si alguno abre, está vivo.
    // Evita depender de ICMP que requiere privilegios.
    let ports = [80, 445, 22, 53];
    for &port in &ports {
        let res = scanner::scan_port(ip, port, timeout_ms).await;
        if res.state == "open" {
            return (true, Some(start.elapsed().as_millis()));
        }
    }
    // Fallback: intenta conectar a 80 con timeout un poco mayor y mide si hay respuesta (aunque cerrado, si hay RST rápido indica host vivo vs timeout)
    // Simplificamos: si no abrió nada, lo marcamos no vivo por ahora
    (false, None)
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
                HostInfo {
                    ip: ip.to_string(),
                    hostname: None, // resolución inversa opcional: lookup_address
                    mac: None,      // requiere ARP table o raw sockets (privilegios)
                    vendor: None,
                    is_alive: true,
                    open_ports,
                    latency_ms: latency,
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
    hosts
}
