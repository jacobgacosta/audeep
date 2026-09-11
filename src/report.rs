use crate::hardware::HardwareReport;
use crate::network::HostInfo;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub generated_at: DateTime<Utc>,
    pub hardware: HardwareReport,
    pub network: NetworkSummary,
    pub hosts: Vec<HostInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkSummary {
    pub local_subnet: Option<String>,
    pub total_hosts_alive: usize,
    pub scan_duration_secs: f64,
    pub total_vulnerabilities: usize,
}

impl AuditReport {
    pub fn new(hardware: HardwareReport, hosts: Vec<HostInfo>, local_subnet: Option<String>, duration_secs: f64) -> Self {
        let total = hosts.len();
        let total_vulns = hosts.iter().map(|h| h.vulnerabilities.len()).sum();
        Self {
            generated_at: Utc::now(),
            hardware,
            network: NetworkSummary {
                local_subnet,
                total_hosts_alive: total,
                scan_duration_secs: duration_secs,
                total_vulnerabilities: total_vulns,
            },
            hosts,
        }
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn save_json(&self, path: &Path) -> std::io::Result<()> {
        let json = self.to_json_pretty().unwrap_or_else(|_| "{}".to_string());
        fs::write(path, json)
    }

    pub fn to_html(&self) -> String {
        let hosts_rows = self.hosts.iter().map(|h| {
            let ports = if h.open_ports.is_empty() {
                "<span class='muted'>ninguno (o filtrado)</span>".to_string()
            } else {
                h.open_ports.iter().map(|p| {
                    let banner = p.banner.as_ref().map(|b| format!("<br><small>{}</small>", html_escape(b))).unwrap_or_default();
                    let svc = p.service_hint.as_ref().map(|s| format!(" ({})", s)).unwrap_or_default();
                    format!("<span class='tag'>{}{} {}{}</span>", p.port, svc, p.state, banner)
                }).collect::<Vec<_>>().join(" ")
            };
            let vulns = if h.vulnerabilities.is_empty() {
                "<span class='muted'>—</span>".to_string()
            } else {
                h.vulnerabilities.iter().map(|v| {
                    let color = match v.severity.as_str() {
                        "critica" => "#ef4444",
                        "alta" => "#f59e0b",
                        "media" => "#eab308",
                        _ => "#9aa4b2",
                    };
                    format!(
                        "<span class='tag' style='border-color:{}'><b>{}</b> <span style='color:{}'>{}</span> :{}<br><small>{}</small></span>",
                        color,
                        html_escape(&v.cve),
                        color,
                        html_escape(&v.severity),
                        v.port,
                        html_escape(&v.description)
                    )
                }).collect::<Vec<_>>().join(" ")
            };
            let vendor = h.vendor.clone().unwrap_or_else(|| "—".to_string());
            let mac = h.mac.clone().unwrap_or_else(|| "—".to_string());
            let latency = h.latency_ms.map(|v| format!("{} ms", v)).unwrap_or_else(|| "—".to_string());
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&h.ip),
                html_escape(&h.hostname.clone().unwrap_or_else(|| "—".to_string())),
                html_escape(&mac),
                html_escape(&vendor),
                latency,
                ports,
                vulns
            )
        }).collect::<Vec<_>>().join("\n");

        let disks_rows = self.hardware.disks.iter().map(|d| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.1} / {:.1} GB</td><td>{}</td></tr>",
                html_escape(&d.name),
                html_escape(&d.mount_point),
                html_escape(&d.file_system),
                d.available_gb,
                d.total_gb,
                if d.is_removable { "extraíble" } else { "fijo" }
            )
        }).collect::<Vec<_>>().join("\n");

        let net_ifaces = self.hardware.network_interfaces.iter().map(|n| {
            format!("<tr><td>{}</td><td>{}</td></tr>", html_escape(&n.name), html_escape(&n.mac))
        }).collect::<Vec<_>>().join("\n");

        let subnet = self.network.local_subnet.clone().unwrap_or_else(|| "no detectada".to_string());
        let oui_count: usize = serde_json::from_str::<std::collections::HashMap<String, String>>(include_str!("../assets/oui.json"))
            .map(|m| m.len())
            .unwrap_or(0);

        format!(r#"<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuDeep — Reporte de Auditoría</title>
<style>
:root {{ --bg:#0b0f14; --fg:#e6edf3; --muted:#9aa4b2; --card:#111827; --accent:#38bdf8; --border:#1f2937; }}
*{{box-sizing:border-box}} body{{margin:0;font-family: ui-sans-serif,system-ui,Segoe UI,Roboto,Helvetica,Arial; background:var(--bg); color:var(--fg);}}
header{{padding:28px 20px; border-bottom:1px solid var(--border); position:sticky; top:0; backdrop-filter: blur(8px); background:rgba(11,15,20,0.8)}}
h1{{margin:0;font-size:22px; letter-spacing:0.2px}} .sub{{color:var(--muted); font-size:13px; margin-top:6px}}
.wrap{{max-width:1100px; margin:0 auto; padding:20px}}
.card{{background:var(--card); border:1px solid var(--border); border-radius:16px; padding:18px; margin-bottom:18px}}
.card h2{{margin:0 0 12px 0; font-size:16px}}
.grid{{display:grid; gap:12px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr))}}
.kv{{background:#0f172a; border:1px solid var(--border); border-radius:12px; padding:12px}}
.kv .k{{color:var(--muted); font-size:12px}} .kv .v{{font-weight:600; margin-top:4px}}
table{{width:100%; border-collapse:collapse; font-size:13px}}
th,td{{text-align:left; padding:10px; border-bottom:1px solid var(--border); vertical-align:top}}
th{{color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:0.5px}}
.tag{{display:inline-block; background:#0f172a; border:1px solid var(--border); border-radius:999px; padding:4px 8px; margin:2px; font-size:12px}}
.muted{{color:var(--muted)}}
footer{{color:var(--muted); font-size:12px; text-align:center; padding:18px}}
</style>
</head>
<body>
<header>
  <h1>AuDeep — Reporte de Auditoría de Hardware y Red</h1>
  <div class="sub">Generado: {} · Subred local: {} · Hosts vivos: {} · Duración escaneo: {:.1}s</div>
</header>
<div class="wrap">
  <div class="card">
    <h2>Hardware local — {}</h2>
    <div class="grid">
      <div class="kv"><div class="k">Sistema</div><div class="v">{} {}</div></div>
      <div class="kv"><div class="k">Kernel</div><div class="v">{}</div></div>
      <div class="kv"><div class="k">CPU</div><div class="v">{} ({})<br><span class="muted">{} núcleos físicos / {} lógicos @ {} MHz</span></div></div>
      <div class="kv"><div class="k">Memoria</div><div class="v">{:.1} / {:.1} GB usados</div></div>
      <div class="kv"><div class="k">Uptime</div><div class="v">{} s</div></div>
      <div class="kv"><div class="k">Discos</div><div class="v">{} unidades</div></div>
    </div>
  </div>

  <div class="card">
    <h2>Almacenamiento</h2>
    <table><thead><tr><th>Nombre</th><th>Punto de montaje</th><th>FS</th><th>Espacio</th><th>Tipo</th></tr></thead><tbody>{}</tbody></table>
  </div>

  <div class="card">
    <h2>Interfaces de red (local)</h2>
    <table><thead><tr><th>Interfaz</th><th>MAC</th></tr></thead><tbody>{}</tbody></table>
  </div>

  <div class="card">
    <h2>Hosts en la red ({} vivos) — {} hallazgos</h2>
    <table><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Fabricante (OUI)</th><th>Latencia</th><th>Puertos abiertos</th><th>Vulnerabilidades</th></tr></thead><tbody>{}</tbody></table>
    <p class="muted" style="margin-top:10px">Nota: MAC y fabricante requieren lectura de tabla ARP (sin privilegios). OUI DB: <code>assets/oui.json</code> ({} entradas). Puertos escaneados: {} · Vuln DB: <code>assets/vuln_db.json</code></p>
  </div>
</div>
<footer>AuDeep v0.1.0 · Rust · Reporte offline listo para USB/Raspberry Pi</footer>
</body>
</html>
"#,
        self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        html_escape(&subnet),
        self.network.total_hosts_alive,
        self.network.scan_duration_secs,
        html_escape(&self.hardware.hostname),
        html_escape(&self.hardware.os_name),
        html_escape(&self.hardware.os_version),
        html_escape(&self.hardware.kernel_version),
        html_escape(&self.hardware.cpu.brand),
        html_escape(&self.hardware.cpu.vendor),
        self.hardware.cpu.cores_physical.unwrap_or(0),
        self.hardware.cpu.cores_logical,
        self.hardware.cpu.frequency_mhz,
        self.hardware.memory.used_gb,
        self.hardware.memory.total_gb,
        self.hardware.uptime_secs,
        self.hardware.disks.len(),
        disks_rows,
        net_ifaces,
        self.hosts.len(),
        self.network.total_vulnerabilities,
        hosts_rows,
        oui_count,
        crate::scanner::COMMON_PORTS.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        )
    }

    pub fn save_html(&self, path: &Path) -> std::io::Result<()> {
        fs::write(path, self.to_html())
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
