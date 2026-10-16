use crate::arp::{arp_table_snapshot, is_locally_administered};
use crate::scanner::{self, PortResult, Probe};
use crate::vuln::Finding;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

/// Presupuesto de sondeo por puerto/host (una sola fuente de verdad).
pub const PROBE_TIMEOUT_MS: u64 = 400;
/// Techo de hosts a sondear: evita que un /16 se convierta en horas de escaneo.
pub const MAX_HOSTS: usize = 4096;
/// Por debajo de este prefijo el barrido se limita al /24 local.
pub const BIG_NETWORK_PREFIX: u8 = 22;
/// Puertos que se usan como señal de vida rápida antes de recurrir al ping.
pub const ALIVE_PORTS: [u16; 4] = [80, 445, 22, 53];
/// Puerto alto improbable: el barrido solo necesita que el SO resuelva la MAC.
const ARP_TRIGGER_PORT: u16 = 54321;

#[derive(Debug, Clone, Serialize)]
pub struct HostInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    /// De dónde salió el vendor: `oui`, `oui-local`, `hostname`, `mdns`, `ssdp`,
    /// `banner`, `puerto`, `http` o `mdns-nombre`. Separa dato real de deducción.
    pub vendor_source: Option<String>,
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

/// Red local real: IP, prefijo leído de la máscara y CIDR ya calculado.
#[derive(Debug, Clone, Serialize)]
pub struct LocalNet {
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub cidr: String,
}

/// Vendor deducido junto con la fuente que lo respalda.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorGuess {
    pub name: String,
    pub source: &'static str,
}

static OUI_JSON_SMALL: &str = include_str!("../assets/oui.json");
static OUI_JSON_FULL: &str = include_str!("../assets/oui_full.json");

/// OUI curado a mano (pocas entradas, casos propios de esta red).
fn oui_curated() -> &'static HashMap<String, String> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<HashMap<String, String>> = OnceLock::new();
    CACHE.get_or_init(|| serde_json::from_str(OUI_JSON_SMALL).unwrap_or_default())
}

/// Cantidad de prefijos OUI disponibles (se muestra en el reporte).
pub fn oui_count() -> usize {
    oui_registry().len().max(oui_curated().len())
}

/// Registro OUI completo (~40k prefijos), se carga una sola vez.
fn oui_registry() -> &'static HashMap<String, String> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<HashMap<String, String>> = OnceLock::new();
    CACHE.get_or_init(|| serde_json::from_str(OUI_JSON_FULL).unwrap_or_default())
}

fn oui_prefix(mac: &str) -> Option<String> {
    let clean = mac.to_uppercase().replace('-', ":");
    let parts: Vec<&str> = clean.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let prefix = parts[..3].join(":");
    if prefix.len() == 8 {
        Some(prefix)
    } else {
        None
    }
}

/// Vendor por OUI, en orden de confianza: curado → bit de MAC local → registro.
///
/// Si el bit `0x02` está prendido la MAC es aleatoria/local, así que el registro
/// OUI **no** identifica al fabricante real: se dice eso en vez de inventar marca.
pub fn lookup_vendor_guess(mac: &str) -> Option<VendorGuess> {
    if let Some(prefix) = oui_prefix(mac)
        && let Some(v) = oui_curated().get(&prefix)
    {
        return Some(VendorGuess {
            name: v.clone(),
            source: "oui",
        });
    }
    if is_locally_administered(&mac.to_lowercase().replace('-', ":")) {
        return Some(VendorGuess {
            name: "MAC local/aleatoria — fabricante oculto".to_string(),
            source: "oui-local",
        });
    }
    if let Some(prefix) = oui_prefix(mac)
        && let Some(v) = oui_registry().get(&prefix)
    {
        return Some(VendorGuess {
            name: v.clone(),
            source: "oui",
        });
    }
    None
}

/// `true` si `needle` aparece como token completo.
///
/// Evita el clásico falso positivo de buscar `"mi "` y matchear `Miguel-PC`.
pub fn contains_token(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack.match_indices(needle).any(|(i, _)| {
        let before_ok = haystack[..i]
            .chars()
            .next_back()
            .map(|c| !c.is_ascii_alphanumeric())
            .unwrap_or(true);
        let after = i + needle.len();
        let after_ok = haystack[after..]
            .chars()
            .next()
            .map(|c| !c.is_ascii_alphanumeric())
            .unwrap_or(true);
        before_ok && after_ok
    })
}

/// Pistas de fabricante buscadas en nombre/mDNS/SSDP/banner/servicio.
const VENDOR_HINTS: &[(&str, &str)] = &[
    ("jetson", "NVIDIA Jetson"),
    ("tegra", "NVIDIA Jetson"),
    ("nvidia", "NVIDIA"),
    ("xiaomi", "Xiaomi"),
    ("redmi", "Xiaomi (Redmi)"),
    ("mibox", "Xiaomi (Mi Box)"),
    ("mi tv", "Xiaomi (Mi TV)"),
    ("tenda", "Tenda"),
    ("espressif", "Espressif"),
    ("esp32", "Espressif (ESP32)"),
    ("esp8266", "Espressif (ESP8266)"),
    ("esphome", "ESPHome"),
    ("raspberry", "Raspberry Pi"),
    ("rpi", "Raspberry Pi"),
    ("bcm27", "Raspberry Pi"),
    ("synology", "Synology"),
    ("diskstation", "Synology"),
    ("printer", "Impresora"),
    ("ipp", "Impresora (IPP)"),
    ("chromecast", "Google Cast"),
    ("googlecast", "Google Cast"),
    ("roku", "Roku"),
    ("shelly", "Shelly"),
    ("tasmota", "Tasmota"),
    ("tp-link", "TP-Link"),
    ("tplink", "TP-Link"),
    ("archer", "TP-Link (Archer)"),
    ("deco", "TP-Link (Deco)"),
    ("huawei", "Huawei"),
    ("ubiquiti", "Ubiquiti"),
    ("unifi", "Ubiquiti (UniFi)"),
    ("mikrotik", "MikroTik"),
    ("airplay", "Apple (AirPlay)"),
    ("apple", "Apple"),
    ("sonos", "Sonos"),
    ("samsung", "Samsung"),
    ("philips", "Philips"),
    ("hue", "Philips Hue"),
];

fn infer_vendor_from_host(h: &HostInfo) -> Option<VendorGuess> {
    let hostname = h.hostname.clone().unwrap_or_default().to_lowercase();
    let mdns = h.mdns_names.join(" ").to_lowercase();
    let ssdp = h.ssdp_location.clone().unwrap_or_default().to_lowercase();
    let banners = h
        .open_ports
        .iter()
        .filter_map(|p| p.banner.as_deref())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let services = h
        .open_ports
        .iter()
        .filter_map(|p| p.service_hint.as_deref())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    let fields: [(&str, &'static str); 5] = [
        (&hostname, "hostname"),
        (&mdns, "mdns"),
        (&ssdp, "ssdp"),
        (&banners, "banner"),
        (&services, "puerto"),
    ];
    for (text, source) in fields {
        if text.is_empty() {
            continue;
        }
        for (needle, name) in VENDOR_HINTS {
            if contains_token(text, needle) {
                return Some(VendorGuess {
                    name: (*name).to_string(),
                    source,
                });
            }
        }
    }
    // Último recurso: el nombre mDNS tal cual, que es dato real y no deducción.
    if !h.mdns_names.is_empty() {
        let first = h.mdns_names[0]
            .split('.')
            .next()
            .unwrap_or("mDNS")
            .to_string();
        return Some(VendorGuess {
            name: format!("mDNS: {first}"),
            source: "mdns-nombre",
        });
    }
    None
}

async fn http_infer_vendor(ip: &str) -> Option<VendorGuess> {
    // Intento real HTTP GET a 80/8080/8000 con timeout 700ms, busca Jetson/RPi
    for port in [80, 8080, 8000] {
        let url = format!("http://{}:{}/", ip, port);
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_millis(700))
            .build()
        {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Ok(resp) = client.get(&url).send().await {
            let headers = format!("{:?}", resp.headers()).to_lowercase();
            let text = resp.text().await.unwrap_or_default().to_lowercase();
            let all = format!("{} {}", headers, text);
            if all.contains("jetson")
                || all.contains("tegra")
                || (all.contains("nvidia") && all.contains("l4t"))
            {
                return Some(VendorGuess {
                    name: "NVIDIA Jetson (deducido por HTTP)".to_string(),
                    source: "http",
                });
            }
            if all.contains("raspberry") || all.contains("rpi") {
                return Some(VendorGuess {
                    name: "Raspberry Pi (deducido por HTTP)".to_string(),
                    source: "http",
                });
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

/// Prefijo CIDR a partir de la máscara. `None` si la máscara no es contigua.
pub fn netmask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let mut prefix = 0u8;
    for i in (0..32).rev() {
        if bits & (1u32 << i) != 0 {
            prefix += 1;
        } else {
            break;
        }
    }
    let expected = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    if bits == expected { Some(prefix) } else { None }
}

/// Dirección de red (bits de host en cero).
pub fn network_of(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = match prefix {
        0 => 0u32,
        32.. => u32::MAX,
        _ => u32::MAX << (32 - prefix),
    };
    Ipv4Addr::from(u32::from(ip) & mask)
}

/// Dirección de broadcast de la red.
pub fn broadcast_of(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = match prefix {
        0 => 0u32,
        32.. => u32::MAX,
        _ => u32::MAX << (32 - prefix),
    };
    Ipv4Addr::from(u32::from(network_of(ip, prefix)) | !mask)
}

pub fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    network_of(a, prefix) == network_of(b, prefix)
}

/// Hosts utilizables de la red, con techo de seguridad `MAX_HOSTS`.
pub fn hosts_in_subnet(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    if prefix >= 31 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let last = u32::from(broadcast_of(ip, prefix));
    let mut cur = u32::from(network_of(ip, prefix)) + 1;
    while cur < last {
        out.push(Ipv4Addr::from(cur));
        if out.len() >= MAX_HOSTS {
            break;
        }
        cur += 1;
    }
    out
}

/// Alcance del barrido: en redes enormes se limita al /24 propio.
pub fn sweep_scope(ip: Ipv4Addr, prefix: u8) -> (Ipv4Addr, u8) {
    if prefix == 0 || prefix < BIG_NETWORK_PREFIX {
        (ip, 24)
    } else {
        (ip, prefix)
    }
}

/// Red local real: lee la máscara de la interfaz (if-addrs) en vez de asumir /24.
pub fn local_net() -> Option<LocalNet> {
    let preferred = get_local_ipv4();
    let candidates: Vec<LocalNet> = if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .filter_map(|i| {
            let if_addrs::Interface { name: _, addr, .. } = i;
            match addr {
                if_addrs::IfAddr::V4(v4) if !v4.is_loopback() && !v4.ip.is_unspecified() => {
                    let prefix = netmask_to_prefix(v4.netmask).unwrap_or(v4.prefixlen);
                    Some(LocalNet {
                        ip: v4.ip,
                        prefix,
                        cidr: format!("{}/{}", network_of(v4.ip, prefix), prefix),
                    })
                }
                _ => None,
            }
        })
        .collect();

    if candidates.is_empty() {
        return None;
    }
    if let Some(p) = preferred
        && let Some(found) = candidates.iter().find(|c| c.ip == p)
    {
        return Some(found.clone());
    }
    if let Some(private) = candidates
        .iter()
        .find(|c| c.ip.is_private() && !c.ip.is_link_local())
    {
        return Some(private.clone());
    }
    candidates.into_iter().next()
}

pub fn local_subnet_cidr() -> Option<String> {
    local_net().map(|n| n.cidr)
}

/// Barrido ARP sin privilegios.
///
/// Manda un UDP a cada host de la red para forzar la resolución ARP (el paquete
/// no importa, el ARP sí) y después lee la tabla del sistema. Es la vía rápida y
/// fiable de saber quién está en la LAN, sin esperar timeouts TCP host por host.
pub async fn arp_sweep(net: &LocalNet) -> HashMap<String, String> {
    let (scope_ip, scope_prefix) = sweep_scope(net.ip, net.prefix);
    let targets = hosts_in_subnet(scope_ip, scope_prefix);
    if targets.is_empty() {
        return arp_table_snapshot();
    }
    let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
        return arp_table_snapshot();
    };
    for round in 0..2 {
        for ip in &targets {
            // El error de send es esperable (host inexistente): lo que importa es el ARP.
            let _ = sock.send_to(&[0u8; 1], (*ip, ARP_TRIGGER_PORT)).await;
        }
        let settle = if round == 0 { 400 } else { 250 };
        tokio::time::sleep(Duration::from_millis(settle)).await;
    }
    arp_table_snapshot()
}

async fn is_host_alive(ip: IpAddr, timeout_ms: u64) -> (bool, Option<u128>) {
    let start = std::time::Instant::now();
    // RST o puerto abierto: prueba positiva de vida, sin depender del ping.
    for &port in ALIVE_PORTS.iter() {
        let (probe, _) = scanner::probe_port(ip, port, timeout_ms).await;
        if probe == Probe::Refused || probe.is_open() {
            return (true, Some(start.elapsed().as_millis()));
        }
    }
    if ping_host(ip, timeout_ms).await {
        return (true, Some(start.elapsed().as_millis()));
    }
    (false, None)
}

/// `TTL=` es el único marcador de la salida de `ping` que no se traduce.
///
/// El código viejo daba por vivo cualquier salida que no contuviera
/// "Request timed out" / "100% loss": con el ping en otro idioma, o con
/// "Destination host unreachable", eso convertía hosts inexistentes en vivos.
pub fn ping_reply_is_alive(stdout: &str) -> bool {
    stdout.contains("TTL=") || stdout.contains("ttl=")
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
        let secs = timeout_ms.div_ceil(1000).to_string();
        let mut c = tokio::process::Command::new("ping");
        c.args(["-c", "1", "-W", &secs, &ip_str]);
        c
    };

    // Evitar colgarse: timeout global 1.5x
    let res = tokio::time::timeout(Duration::from_millis(timeout_ms + 500), cmd.output()).await;

    match res {
        Ok(Ok(out)) => ping_reply_is_alive(&String::from_utf8_lossy(&out.stdout)),
        _ => false,
    }
}

async fn try_resolve_hostname(ip: IpAddr) -> Option<String> {
    let ip_copy = ip;
    // timeout 500ms para no bloquear discovery
    let res = tokio::time::timeout(
        Duration::from_millis(500),
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

/// Descubrimiento ARP-first: primero quién responde ARP, después puertos.
pub async fn discover_hosts(timeout_ms: u64, max_concurrency: usize) -> Vec<HostInfo> {
    let Some(net) = local_net() else {
        return Vec::new();
    };

    let arp = arp_sweep(&net).await;
    let arp_hosts: HashMap<Ipv4Addr, String> = arp
        .iter()
        .filter_map(|(ip, mac)| {
            let v4 = ip.parse::<Ipv4Addr>().ok()?;
            if v4 == net.ip || !same_subnet(v4, net.ip, net.prefix) {
                return None;
            }
            Some((v4, mac.clone()))
        })
        .collect();

    // Si el ARP no devolvió nada (red rara o tabla inaccesible) se cae al
    // barrido clásico TCP+ping, acotado al alcance del sweep.
    let (scope_ip, scope_prefix) = sweep_scope(net.ip, net.prefix);
    let candidates: Vec<Ipv4Addr> = if arp_hosts.is_empty() {
        hosts_in_subnet(scope_ip, scope_prefix)
            .into_iter()
            .filter(|ip| *ip != net.ip)
            .collect()
    } else {
        let mut v: Vec<Ipv4Addr> = arp_hosts.keys().copied().collect();
        v.sort();
        v
    };

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrency.max(1)));
    let mut tasks = Vec::new();

    for ip in candidates {
        let sem = semaphore.clone();
        let arp_mac = arp_hosts.get(&ip).cloned();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let (alive, latency) = match &arp_mac {
                // Respondió ARP hace menos de un segundo: está vivo, sin gastar timeouts.
                Some(_) => (true, None),
                None => is_host_alive(IpAddr::V4(ip), timeout_ms).await,
            };
            if !alive {
                return None;
            }
            let open_ports = scanner::scan_common_ports(IpAddr::V4(ip), timeout_ms).await;
            let vulnerabilities = crate::vuln::check_host(&open_ports);
            let hostname = try_resolve_hostname(IpAddr::V4(ip)).await;
            let guess = arp_mac.as_deref().and_then(lookup_vendor_guess);
            Some(HostInfo {
                ip: ip.to_string(),
                hostname,
                mac: arp_mac,
                vendor: guess.as_ref().map(|g| g.name.clone()),
                vendor_source: guess.as_ref().map(|g| g.source.to_string()),
                is_alive: true,
                open_ports,
                latency_ms: latency,
                vulnerabilities,
                mdns_names: Vec::new(),
                ssdp_location: None,
            })
        }));
    }

    let mut alive_hosts = Vec::new();
    for t in tasks {
        if let Ok(Some(host)) = t.await {
            alive_hosts.push(host);
        }
    }

    // Host local al frente (su MAC no está en su propia tabla ARP)
    let local_open = scanner::scan_common_ports(IpAddr::V4(net.ip), timeout_ms).await;
    let local_vulns = crate::vuln::check_host(&local_open);
    alive_hosts.insert(
        0,
        HostInfo {
            ip: net.ip.to_string(),
            hostname: hostname::get().ok().and_then(|h| h.into_string().ok()),
            mac: None,
            vendor: None,
            vendor_source: None,
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

pub async fn enrich_with_arp(mut hosts: Vec<HostInfo>) -> Vec<HostInfo> {
    let arp = arp_table_snapshot();
    let net = local_net();

    for h in &mut hosts {
        if h.mac.is_none()
            && let Some(mac) = arp.get(&h.ip)
        {
            h.mac = Some(mac.clone());
            if let Some(guess) = lookup_vendor_guess(mac) {
                h.vendor = Some(guess.name);
                h.vendor_source = Some(guess.source.to_string());
            }
        }
        // Intentar resolver hostname si aún no tiene (con timeout corto)
        if h.hostname.is_none()
            && let Ok(ip) = h.ip.parse::<IpAddr>()
        {
            h.hostname = try_resolve_hostname(ip).await;
        }
    }

    // Merge: añadir hosts que están en ARP pero no fueron detectados como vivos
    // (dispositivos silenciosos que no exponen puertos pero sí responden ARP).
    let known: HashSet<String> = hosts.iter().map(|h| h.ip.clone()).collect();
    for (ip, mac) in arp.iter() {
        if known.contains(ip) {
            continue;
        }
        let Ok(v4) = ip.parse::<Ipv4Addr>() else {
            continue;
        };
        match &net {
            Some(n) => {
                if v4 == n.ip
                    || !same_subnet(v4, n.ip, n.prefix)
                    || v4 == broadcast_of(n.ip, n.prefix)
                {
                    continue;
                }
            }
            None => {
                if v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified() {
                    continue;
                }
            }
        }
        let guess = lookup_vendor_guess(mac);
        let hostname = try_resolve_hostname(IpAddr::V4(v4)).await;
        hosts.push(HostInfo {
            ip: ip.clone(),
            hostname,
            mac: Some(mac.clone()),
            vendor: guess.as_ref().map(|g| g.name.clone()),
            vendor_source: guess.as_ref().map(|g| g.source.to_string()),
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
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let wait = remaining.min(Duration::from_millis(200));
            for rx in &receivers {
                while let Ok(event) = rx.recv_timeout(wait) {
                    if let mdns_sd::ServiceEvent::ServiceResolved(info) = event {
                        let hostname = info.get_hostname().trim_end_matches('.').to_string();
                        for addr in info.get_addresses() {
                            let ip_str = addr.to_string();
                            map.entry(ip_str).or_default().push(hostname.clone());
                            // también mapear fullname
                            let fullname = info.get_fullname().trim_end_matches('.').to_string();
                            if fullname != hostname
                                && let Some(v) = map.get_mut(&addr.to_string())
                                && !v.contains(&fullname)
                            {
                                v.push(fullname.clone());
                            }
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
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
        tokio::time::sleep(Duration::from_millis(400)).await;
        let _ = s2.send_to(msearch, "239.255.255.250:1900").await;
    });
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms.min(3000));
    let mut buf = vec![0u8; 2048];
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let recv_fut = sock_clone.recv_from(&mut buf);
        match tokio::time::timeout(remaining.min(Duration::from_millis(400)), recv_fut).await {
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
                    }
                }
                let ip = peer.ip().to_string();
                let val = location
                    .or(server)
                    .unwrap_or_else(|| text.lines().next().unwrap_or("").to_string());
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
    let (mdns_map, ssdp_map) =
        tokio::join!(discover_mdns_map(timeout_ms), discover_ssdp_map(timeout_ms));
    let existing_ips: HashSet<String> = hosts.iter().map(|h| h.ip.clone()).collect();
    let net = local_net();

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
        }
        // Si no hay vendor o solo tenemos el aviso de MAC local, deducir por
        // nombre/mDNS/SSDP/banner y, si hay HTTP, confirmar con la web del equipo.
        let needs_infer = h.vendor.is_none() || h.vendor_source.as_deref() == Some("oui-local");
        if needs_infer {
            if let Some(guess) = infer_vendor_from_host(h) {
                h.vendor = Some(guess.name);
                h.vendor_source = Some(guess.source.to_string());
            } else if h
                .open_ports
                .iter()
                .any(|p| p.port == 80 || p.port == 8080 || p.port == 8000)
                && let Some(guess) = http_infer_vendor(&h.ip).await
            {
                h.vendor = Some(guess.name);
                h.vendor_source = Some(guess.source.to_string());
            }
        }
    }

    let in_local_net = |ip: &str| -> bool {
        let Ok(v4) = ip.parse::<Ipv4Addr>() else {
            return false;
        };
        match &net {
            Some(n) => {
                v4 != n.ip && v4 != broadcast_of(n.ip, n.prefix) && same_subnet(v4, n.ip, n.prefix)
            }
            None => !v4.is_multicast() && !v4.is_broadcast() && !v4.is_unspecified(),
        }
    };

    // Añadir hosts descubiertos solo por mDNS (ej. impresoras silenciosas)
    for (ip, names) in mdns_map {
        if existing_ips.contains(&ip) || !in_local_net(&ip) || hosts.iter().any(|h| h.ip == ip) {
            continue;
        }
        let hostname = names.first().cloned();
        // `ssdp_location` se resuelve antes de mover `ip` al struct.
        let ssdp_location = ssdp_map.get(&ip).cloned();
        hosts.push(HostInfo {
            ip,
            hostname,
            mac: None,
            vendor: None,
            vendor_source: None,
            is_alive: true,
            open_ports: Vec::new(),
            latency_ms: None,
            vulnerabilities: Vec::new(),
            mdns_names: names,
            ssdp_location,
        });
    }

    // Añadir hosts descubiertos solo por SSDP
    for (ip, loc) in ssdp_map {
        if existing_ips.contains(&ip) || !in_local_net(&ip) || hosts.iter().any(|h| h.ip == ip) {
            continue;
        }
        hosts.push(HostInfo {
            ip,
            hostname: None,
            mac: None,
            vendor: None,
            vendor_source: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ip: &str, hostname: Option<&str>) -> HostInfo {
        HostInfo {
            ip: ip.to_string(),
            hostname: hostname.map(|s| s.to_string()),
            mac: None,
            vendor: None,
            vendor_source: None,
            is_alive: true,
            open_ports: Vec::new(),
            latency_ms: None,
            vulnerabilities: Vec::new(),
            mdns_names: Vec::new(),
            ssdp_location: None,
        }
    }

    #[test]
    fn netmask_to_prefix_valid_and_invalid() {
        assert_eq!(
            netmask_to_prefix("255.255.255.0".parse().unwrap()),
            Some(24)
        );
        assert_eq!(
            netmask_to_prefix("255.255.254.0".parse().unwrap()),
            Some(23)
        );
        assert_eq!(netmask_to_prefix("255.255.0.0".parse().unwrap()), Some(16));
        assert_eq!(
            netmask_to_prefix("255.255.255.252".parse().unwrap()),
            Some(30)
        );
        assert_eq!(
            netmask_to_prefix("255.255.255.255".parse().unwrap()),
            Some(32)
        );
        assert_eq!(netmask_to_prefix("0.0.0.0".parse().unwrap()), Some(0));
        assert_eq!(
            netmask_to_prefix("255.0.255.0".parse().unwrap()),
            None,
            "mascara no contigua"
        );
    }

    #[test]
    fn network_and_broadcast_math() {
        let ip: Ipv4Addr = "192.168.1.37".parse().unwrap();
        assert_eq!(network_of(ip, 24).to_string(), "192.168.1.0");
        assert_eq!(broadcast_of(ip, 24).to_string(), "192.168.1.255");
        assert_eq!(network_of(ip, 23).to_string(), "192.168.0.0");
        assert_eq!(broadcast_of(ip, 23).to_string(), "192.168.1.255");
        assert_eq!(network_of(ip, 16).to_string(), "192.168.0.0");
    }

    #[test]
    fn hosts_in_subnet_is_bounded_and_correct() {
        let ip: Ipv4Addr = "192.168.1.7".parse().unwrap();
        let hosts = hosts_in_subnet(ip, 24);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts.first().unwrap().to_string(), "192.168.1.1");
        assert_eq!(hosts.last().unwrap().to_string(), "192.168.1.254");
        assert_eq!(hosts_in_subnet("10.0.0.1".parse().unwrap(), 30).len(), 2);
        assert!(hosts_in_subnet(ip, 31).is_empty());
        assert!(hosts_in_subnet(ip, 32).is_empty());
        assert_eq!(
            hosts_in_subnet(ip, 8).len(),
            MAX_HOSTS,
            "red enorme acotada"
        );
    }

    #[test]
    fn big_networks_sweep_only_local_24() {
        let ip: Ipv4Addr = "10.5.9.3".parse().unwrap();
        assert_eq!(sweep_scope(ip, 16), (ip, 24));
        assert_eq!(sweep_scope(ip, 8), (ip, 24));
        assert_eq!(sweep_scope(ip, 24), (ip, 24));
        assert_eq!(sweep_scope(ip, 23), (ip, 23));
        assert_eq!(sweep_scope(ip, 0), (ip, 24));
    }

    #[test]
    fn same_subnet_checks() {
        let a: Ipv4Addr = "192.168.1.7".parse().unwrap();
        assert!(same_subnet(a, "192.168.1.200".parse().unwrap(), 24));
        assert!(!same_subnet(a, "192.168.2.200".parse().unwrap(), 24));
        assert!(same_subnet(a, "192.168.0.200".parse().unwrap(), 23));
    }

    #[test]
    fn token_match_avoids_partial_words() {
        assert!(contains_token("mi tv box", "mi tv"));
        assert!(contains_token("xiaomi-airpurifier", "xiaomi"));
        assert!(!contains_token("miguel-pc", "mi"));
        assert!(!contains_token("dominic", "mi"));
        assert!(!contains_token("", "mi"));
        assert!(
            contains_token("impresora-hp", "impresora"),
            "prefijo de token vale"
        );
    }

    #[test]
    fn ping_output_is_judged_by_ttl_only() {
        assert!(ping_reply_is_alive(
            "Respuesta desde 192.168.1.1: bytes=32 tiempo=2ms TTL=64"
        ));
        assert!(ping_reply_is_alive(
            "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.2 ms"
        ));
        assert!(!ping_reply_is_alive("Request timed out."));
        assert!(!ping_reply_is_alive(
            "Tiempo de espera agotado para esta solicitud."
        ));
        assert!(!ping_reply_is_alive(
            "Reply from 192.168.1.7: Destination host unreachable."
        ));
        assert!(!ping_reply_is_alive(
            "PING: transmit failed. General failure."
        ));
        assert!(!ping_reply_is_alive(
            "Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),"
        ));
    }

    #[test]
    fn vendor_guess_prefers_curated_then_flags_random_mac() {
        let g = lookup_vendor_guess("24-a6-5e-00-00-01").expect("OUI curado (Tenda)");
        assert_eq!(g.source, "oui");
        let local = lookup_vendor_guess("02:11:22:33:44:55").expect("MAC de administracion local");
        assert_eq!(local.source, "oui-local");
        assert!(local.name.contains("aleatoria"));
        assert!(lookup_vendor_guess("zz:zz:zz:zz:zz:zz").is_none());
    }

    #[test]
    fn infer_vendor_from_hostname_and_mdns() {
        let mut h = host("192.168.1.15", Some("jetson-dev"));
        let g = infer_vendor_from_host(&h).unwrap();
        assert_eq!(g.name, "NVIDIA Jetson");
        assert_eq!(g.source, "hostname");

        h.hostname = Some("miguel-pc".to_string());
        h.mdns_names = vec!["impresora-hp.local".to_string()];
        let g = infer_vendor_from_host(&h).unwrap();
        assert_eq!(g.source, "mdns-nombre");
        assert_eq!(g.name, "mDNS: impresora-hp");

        h.mdns_names = Vec::new();
        assert!(
            infer_vendor_from_host(&h).is_none(),
            "ni 'miguel' ni 'pc' son marcas"
        );
    }
}
