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
    #[serde(default)]
    pub mdns_names: Vec<String>,
    #[serde(default)]
    pub ssdp_location: Option<String>,
}

static OUI_JSON_SMALL: &str = include_str!("../assets/oui.json");
static OUI_JSON_FULL: &str = include_str!("../assets/oui_full.json");

fn oui_db() -> &'static HashMap<String, String> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<HashMap<String, String>> = OnceLock::new();
    CACHE.get_or_init(|| {
        // Intentar full primero, fallback a small
        let mut map: HashMap<String, String> = serde_json::from_str(OUI_JSON_FULL).unwrap_or_default();
        if map.is_empty() {
            map = serde_json::from_str(OUI_JSON_SMALL).unwrap_or_default();
        } else {
            // Merge small (curated) sobreescribe full para casos especiales como Router Tenda
            if let Ok(small) = serde_json::from_str::<HashMap<String, String>>(OUI_JSON_SMALL) {
                for (k, v) in small {
                    map.insert(k, v);
                }
            }
        }
        map
    })
}

pub fn lookup_vendor(mac: &str) -> Option<String> {
    let clean = mac.to_uppercase().replace('-', ":");
    let parts: Vec<&str> = clean.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let prefix = parts[..3].join(":");
    if prefix.len() != 8 {
        return None;
    }
    if let Some(v) = oui_db().get(&prefix) {
        return Some(v.clone());
    }
    // Detectar MAC localmente administrada (bit 1 del primer octeto)
    // Segundo hex digit: 2,6,A,E indica locally administered
    if let Some(first_octet) = parts.first() {
        if first_octet.len() == 2 {
            if let Ok(byte) = u8::from_str_radix(first_octet, 16) {
                if byte & 0x02 != 0 {
                    return Some("Locally Administered (virtual/docker)".to_string());
                }
            }
        }
    }
    None
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
        Ok(Ok(out)) => {
            // En Windows, éxito si contiene TTL=, además de exit 0
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Si no hay TTL, no es reply real (ej. 100% loss pero exit 0 en algunos casos)
                // Pero ya filtramos por success, que en Windows es confiable (0 solo con TTL)
                return stdout.contains("TTL=") || stdout.contains("ttl=") || !stdout.contains("Request timed out") && !stdout.contains("100% loss");
            }
            false
        }
        _ => false,
    }
}

async fn try_resolve_hostname(ip: IpAddr) -> Option<String> {
    let ip_copy = ip;
    // timeout 500ms para no bloquear discovery
    let res = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip_copy).ok()),
    )
    .await;
    match res {
        Ok(Ok(Some(name))) => {
            // Filtrar si el nombre es igual a la IP (no resolvió)
            if name == ip_copy.to_string() {
                None
            } else {
                Some(name.trim_end_matches('.').to_string())
            }
        }
        _ => None,
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
                // para hosts vivos, hacer escaneo rápido de puertos comunes + reverse DNS
                let open_ports = scanner::scan_common_ports(IpAddr::V4(ip), timeout_ms).await;
                let vulnerabilities = crate::vuln::check_host(&open_ports);
                let hostname = try_resolve_hostname(IpAddr::V4(ip)).await;
                    HostInfo {
                    ip: ip.to_string(),
                    hostname,
                    mac: None,
                    vendor: None,
                    is_alive: true,
                    open_ports,
                    latency_ms: latency,
                    vulnerabilities,
                    mdns_names: Vec::new(),
                    ssdp_location: None,
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
                    mdns_names: Vec::new(),
                    ssdp_location: None,
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
            mdns_names: Vec::new(),
            ssdp_location: None,
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

pub async fn enrich_with_arp(mut hosts: Vec<HostInfo>) -> Vec<HostInfo> {
    let arp = arp_table_snapshot();
    for h in &mut hosts {
        if let Some(mac) = arp.get(&h.ip) {
            h.mac = Some(mac.clone());
            h.vendor = lookup_vendor(mac);
        }
        // Intentar resolver hostname si aún no tiene (con timeout corto)
        if h.hostname.is_none() {
            if let Ok(ip) = h.ip.parse::<IpAddr>() {
                h.hostname = try_resolve_hostname(ip).await;
            }
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
        let hostname = if let Ok(ip_addr) = ip.parse::<IpAddr>() {
            try_resolve_hostname(ip_addr).await
        } else {
            None
        };
        hosts.push(HostInfo {
            ip: ip.clone(),
            hostname,
            mac: Some(mac.clone()),
            vendor,
            is_alive: true,
            open_ports: Vec::new(),
            latency_ms: None,
            vulnerabilities: Vec::new(),
            mdns_names: Vec::new(),
            ssdp_location: None,
        });
    }
    hosts.sort_by(|a, b| a.ip.cmp(&b.ip));
    hosts
}

pub async fn discover_mdns_map(timeout_ms: u64) -> HashMap<String, Vec<String>> {
    let timeout_ms = timeout_ms.min(3000);
    let result = tokio::task::spawn_blocking(move || {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        let mdns = match mdns_sd::ServiceDaemon::new() {
            Ok(d) => d,
            Err(_) => return map,
        };
        let service_types = [
            "_http._tcp.local.",
            "_https._tcp.local.",
            "_ipp._tcp.local.",
            "_ipps._tcp.local.",
            "_smb._tcp.local.",
            "_afpovertcp._tcp.local.",
            "_hap._tcp.local.",
            "_esphomelib._tcp.local.",
            "_googlecast._tcp.local.",
        ];
        let mut receivers = Vec::new();
        for st in service_types.iter() {
            if let Ok(r) = mdns.browse(st) {
                receivers.push(r);
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let wait = remaining.min(std::time::Duration::from_millis(200));
            for rx in &receivers {
                while let Ok(event) = rx.recv_timeout(wait) {
                    if let mdns_sd::ServiceEvent::ServiceResolved(info) = event {
                        let hostname = info.get_hostname().trim_end_matches('.').to_string();
                        for addr in info.get_addresses() {
                            let ip_str = addr.to_string();
                            map.entry(ip_str).or_default().push(hostname.clone());
                            // también mapear fullname
                            let fullname = info.get_fullname().trim_end_matches('.').to_string();
                            if fullname != hostname {
                                if let Some(v) = map.get_mut(&addr.to_string()) {
                                    if !v.contains(&fullname) { v.push(fullname.clone()); }
                                }
                            }
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let _ = mdns.shutdown();
        map
    })
    .await;
    result.unwrap_or_default()
}

pub async fn discover_ssdp_map(timeout_ms: u64) -> HashMap<String, String> {
    use tokio::net::UdpSocket;
    let mut map: HashMap<String, String> = HashMap::new();
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return map,
    };
    let _ = sock.set_broadcast(true);
    let msearch = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\nMX: 2\r\n\r\n";
    let _ = sock.send_to(msearch, "239.255.255.250:1900").await;
    // reintento para dispositivos lentos
    let sock_clone = std::sync::Arc::new(sock);
    let s2 = sock_clone.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let _ = s2.send_to(msearch, "239.255.255.250:1900").await;
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.min(3000));
    let mut buf = vec![0u8; 2048];
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let recv_fut = sock_clone.recv_from(&mut buf);
        match tokio::time::timeout(remaining.min(std::time::Duration::from_millis(400)), recv_fut).await {
            Ok(Ok((n, peer))) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                let mut location = None;
                let mut server = None;
                for line in text.lines() {
                    let l = line.trim();
                    if l.to_uppercase().starts_with("LOCATION:") {
                        location = Some(l[9..].trim().to_string());
                    } else if l.to_uppercase().starts_with("SERVER:") {
                        server = Some(l[7..].trim().to_string());
                    } else if l.to_uppercase().starts_with("ST:") || l.to_uppercase().starts_with("NT:") {
                        // service type, podría usarse para vendor
                    }
                }
                let ip = peer.ip().to_string();
                let val = location.or(server).unwrap_or_else(|| text.lines().next().unwrap_or("").to_string());
                if !val.is_empty() {
                    map.entry(ip).or_insert(val);
                }
            }
            _ => break,
        }
    }
    map
}

pub async fn enrich_with_mdns_ssdp(mut hosts: Vec<HostInfo>, timeout_ms: u64) -> Vec<HostInfo> {
    // Ejecutar mDNS y SSDP en paralelo
    let (mdns_map, ssdp_map) = tokio::join!(discover_mdns_map(timeout_ms), discover_ssdp_map(timeout_ms));
    let existing_ips: std::collections::HashSet<String> = hosts.iter().map(|h| h.ip.clone()).collect();
    // Enriquecer hosts existentes
    for h in &mut hosts {
        if let Some(names) = mdns_map.get(&h.ip) {
            h.mdns_names = names.clone();
            if h.hostname.is_none() && !names.is_empty() {
                h.hostname = Some(names[0].clone());
            }
        }
        if let Some(loc) = ssdp_map.get(&h.ip) {
            h.ssdp_location = Some(loc.clone());
            // Si no hay vendor, intentar inferir de SSDP server
            if h.vendor.is_none() && (loc.to_lowercase().contains("xiaomi") || loc.to_lowercase().contains("tenda") || loc.to_lowercase().contains("espressif")) {
                // vendor ya resuelto por OUI, pero dejamos ssdp como pista
            }
        }
    }
    // Añadir hosts descubiertos solo por mDNS/SSDP que no estaban en lista (ej. impresoras silenciosas)
    for (ip, names) in mdns_map {
        if existing_ips.contains(&ip) { continue; }
        if ip.parse::<IpAddr>().is_err() { continue; }
        if ip.starts_with("224.") || ip.starts_with("239.") { continue; }
        if ip.ends_with(".0") || ip.ends_with(".255") { continue; }
        if let Some(local) = get_local_ipv4() {
            if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
                let lo = local.octets();
                let o = parsed.octets();
                if o[0]!=lo[0] || o[1]!=lo[1] || o[2]!=lo[2] { continue; }
            }
        }
        let hostname = names.first().cloned();
        hosts.push(HostInfo {
            ip: ip.clone(),
            hostname,
            mac: None,
            vendor: None,
            is_alive: true,
            open_ports: Vec::new(),
            latency_ms: None,
            vulnerabilities: Vec::new(),
            mdns_names: names,
            ssdp_location: ssdp_map.get(&ip).cloned(),
        });
    }
    for (ip, loc) in ssdp_map {
        if existing_ips.contains(&ip) { continue; }
        if hosts.iter().any(|h| h.ip==ip) { continue; }
        if ip.parse::<IpAddr>().is_err() { continue; }
        if ip.starts_with("224.") || ip.starts_with("239.") { continue; }
        if ip.ends_with(".0") || ip.ends_with(".255") { continue; }
        if let Some(local) = get_local_ipv4() {
            if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
                let lo = local.octets();
                let o = parsed.octets();
                if o[0]!=lo[0] || o[1]!=lo[1] || o[2]!=lo[2] { continue; }
            }
        }
        hosts.push(HostInfo {
            ip: ip.clone(),
            hostname: None,
            mac: None,
            vendor: None,
            is_alive: true,
            open_ports: Vec::new(),
            latency_ms: None,
            vulnerabilities: Vec::new(),
            mdns_names: Vec::new(),
            ssdp_location: Some(loc),
        });
    }
    hosts.sort_by(|a, b| a.ip.cmp(&b.ip));
    hosts
}
