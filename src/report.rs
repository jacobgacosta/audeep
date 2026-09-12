use crate::hardware::HardwareReport;
use crate::network::HostInfo;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
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
            let mdns = if h.mdns_names.is_empty() { "—".to_string() } else { h.mdns_names.iter().map(|n| html_escape(n)).collect::<Vec<_>>().join("<br>") };
            let ssdp = h.ssdp_location.clone().map(|s| html_escape(&s)).unwrap_or_else(|| "—".to_string());
            // data attributes for JS filtering
            let sev = h.vulnerabilities.iter().map(|v| v.severity.clone()).collect::<Vec<_>>().join(",");
            format!(
                "<tr data-ip='{}' data-hostname='{}' data-vendor='{}' data-sev='{}'><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&h.ip.to_lowercase()),
                html_escape(&h.hostname.clone().unwrap_or_default().to_lowercase()),
                html_escape(&vendor.to_lowercase()),
                sev,
                html_escape(&h.ip),
                html_escape(&h.hostname.clone().unwrap_or_else(|| "—".to_string())),
                html_escape(&mac),
                html_escape(&vendor),
                latency,
                ports,
                vulns,
                mdns,
                ssdp
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

        let sensors_rows = if self.hardware.sensors.is_empty() {
            "<tr><td colspan='4' class='muted'>No se detectaron sensores (normal en Windows/VM)</td></tr>".to_string()
        } else {
            self.hardware.sensors
                .iter()
                .map(|s| {
                    let crit = s.critical_c.map(|c| format!("{:.1}°C", c)).unwrap_or_else(|| "—".to_string());
                    format!(
                        "<tr><td>{}</td><td>{:.1}°C</td><td>{:.1}°C</td><td>{}</td></tr>",
                        html_escape(&s.label),
                        s.temperature_c,
                        s.max_c,
                        html_escape(&crit)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        let subnet = self.network.local_subnet.clone().unwrap_or_else(|| "no detectada".to_string());
        let oui_count: usize = serde_json::from_str::<std::collections::HashMap<String, String>>(include_str!("../assets/oui_full.json"))
            .map(|m| m.len())
            .unwrap_or_else(|_| {
                serde_json::from_str::<std::collections::HashMap<String, String>>(include_str!("../assets/oui.json"))
                    .map(|m| m.len())
                    .unwrap_or(0)
            });
        let cve_count = crate::vuln::load_db().len();

        // Chart data computed in Rust for JS
        let mut vendor_counts: HashMap<String, usize> = HashMap::new();
        let mut port_counts: HashMap<String, usize> = HashMap::new();
        let mut sev_counts: HashMap<String, usize> = HashMap::new();
        for h in &self.hosts {
            let v = h.vendor.clone().unwrap_or_else(|| "Desconocido".to_string());
            *vendor_counts.entry(v).or_insert(0) += 1;
            for p in &h.open_ports { *port_counts.entry(p.port.to_string()).or_insert(0) += 1; }
            for vuln in &h.vulnerabilities { *sev_counts.entry(vuln.severity.clone()).or_insert(0) +=1; }
        }
        let mut vendor_sorted: Vec<_> = vendor_counts.into_iter().collect();
        vendor_sorted.sort_by(|a,b| b.1.cmp(&a.1));
        vendor_sorted.truncate(6);
        let mut port_sorted: Vec<_> = port_counts.into_iter().collect();
        port_sorted.sort_by(|a,b| b.1.cmp(&a.1));
        port_sorted.truncate(8);

        let vendor_labels = vendor_sorted.iter().map(|(k,_)| html_escape(k)).collect::<Vec<_>>().join("|");
        let vendor_vals = vendor_sorted.iter().map(|(_,v)| v.to_string()).collect::<Vec<_>>().join(",");
        let port_labels = port_sorted.iter().map(|(k,_)| k.clone()).collect::<Vec<_>>().join(",");
        let port_vals = port_sorted.iter().map(|(_,v)| v.to_string()).collect::<Vec<_>>().join(",");
        let sev_crit = sev_counts.get("critica").cloned().unwrap_or(0);
        let sev_alta = sev_counts.get("alta").cloned().unwrap_or(0);
        let sev_media = sev_counts.get("media").cloned().unwrap_or(0);
        let sev_baja = sev_counts.get("baja").cloned().unwrap_or(0);
        let total_vulns = self.network.total_vulnerabilities;

        let data_json = serde_json::to_string(&self.hosts).unwrap_or_else(|_| "[]".to_string());
        // Escape for html
        let data_json_escaped = data_json.replace("</", "<\\/");

        let base = format!(r#"<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuDeep — Reporte Mamón</title>
<style>
:root {{ --bg:#fdfbf7; --bg2:#f5f1e8; --fg:#1c1917; --muted:#78716c; --card:#ffffff; --card2:#fffbeb; --accent:#0ea5e9; --accent2:#e11d48; --border:#e7e5e4; --crit:#dc2626; --alta:#d97706; --media:#ca8a04; --baja:#16a34a; }}
*{{box-sizing:border-box}} body{{margin:0;font-family: ui-sans-serif,system-ui,Segoe UI,Roboto,Helvetica,Arial; background: var(--bg); color:var(--fg); min-height:100vh;}}
header{{padding:24px 20px 16px; border-bottom:1px solid var(--border); position:sticky; top:0; z-index:10; backdrop-filter: blur(8px); background:rgba(253,251,247,0.92)}} 
h1{{margin:0;font-size:22px; letter-spacing:-0.3px; color:#1c1917; font-weight:800; font-family: ui-monospace, SFMono-Regular, Menlo, monospace}} h1 span{{color:var(--accent2)}} .sub{{color:var(--muted); font-size:12px; margin-top:4px; font-family: ui-monospace, monospace}}
.wrap{{max-width:1200px; margin:0 auto; padding:20px}}
.card{{background: var(--card); border:1px solid var(--border); border-radius:16px; padding:16px; margin-bottom:16px; box-shadow: 0 1px 3px rgba(0,0,0,0.06), 0 4px 12px rgba(0,0,0,0.04)}}
.card h2{{margin:0 0 10px 0; font-size:12px; letter-spacing:0.8px; text-transform:uppercase; color:var(--muted); font-family: ui-monospace, monospace}}
.grid{{display:grid; gap:10px; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr))}}
.kv{{background:#ffffff; border:1px solid var(--border); border-radius:12px; padding:12px; position:relative}} .kv .k{{color:var(--muted); font-size:10px; text-transform:uppercase; letter-spacing:0.7px; font-family: ui-monospace, monospace}} .kv .v{{font-weight:700; margin-top:4px; font-size:16px}} .kv .v small{{font-weight:400; color:var(--muted); font-size:11px; font-family: ui-monospace, monospace}}
.stats{{display:grid; grid-template-columns: repeat(4, 1fr); gap:10px; margin-bottom:14px}} @media(max-width:800px){{.stats{{grid-template-columns: repeat(2,1fr)}}}}
.stat{{background: #ffffff; border:1px solid var(--border); border-radius:14px; padding:14px; text-align:center}} .stat .num{{font-size:26px; font-weight:800; line-height:1; font-family: ui-monospace, monospace}} .stat .lbl{{color:var(--muted); font-size:11px; margin-top:4px; text-transform:uppercase; letter-spacing:0.6px; font-family: ui-monospace, monospace}}
.charts{{display:grid; grid-template-columns: 1.1fr 1fr 1fr; gap:10px; margin-bottom:16px}} @media(max-width:900px){{.charts{{grid-template-columns:1fr}}}}
.chartBox{{background: #ffffff; border:1px solid var(--border); border-radius:14px; padding:14px}} .chartBox h3{{margin:0 0 8px 0; font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.6px; font-family: ui-monospace, monospace}}
.canv{{width:100%; height:180px; display:block}}
table{{width:100%; border-collapse:collapse; font-size:12px}} th,td{{text-align:left; padding:9px; border-bottom:1px solid var(--border); vertical-align:top; font-family: ui-monospace, monospace; font-size:11px}} th{{color:var(--muted); font-weight:600; font-size:10px; text-transform:uppercase; letter-spacing:0.6px; position:sticky; top:0; background: #fffbeb}} 
.tag{{display:inline-block; background:#fffbeb; border:1px solid var(--border); border-radius:999px; padding:3px 7px; margin:2px; font-size:11px; font-family: ui-monospace, monospace}} .muted{{color:var(--muted)}}
.controls{{display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px}} .controls input, .controls select{{flex:1; min-width:160px; padding:9px 11px; border-radius:8px; border:1px solid var(--border); background:#ffffff; color:var(--fg); outline:none; font-family: ui-monospace, monospace; font-size:12px}} .controls input:focus{{border-color:var(--accent)}}
.btn{{padding:9px 13px; border-radius:8px; border:1px solid var(--border); background: #1c1917; color:#fdfbf7; cursor:pointer; font-weight:600; font-family: ui-monospace, monospace; font-size:12px}} .btn:hover{{background:#292524}}
.badge{{display:inline-block; padding:2px 7px; border-radius:999px; font-size:11px; font-weight:700; border:1px solid transparent; font-family: ui-monospace, monospace}} .bCrit{{background:#fef2f2; color:#991b1b; border-color:#fecaca}} .bAlta{{background:#fffbeb; color:#92400e; border-color:#fde68a}} .bMedia{{background:#fefce8; color:#854d0e; border-color:#fde047}} .bBaja{{background:#f0fdf4; color:#166534; border-color:#bbf7d0}}
.bar{{height:8px; border-radius:999px; background: #1c1917; display:block}} .barWrap{{background:#f5f5f4; border-radius:999px; overflow:hidden; height:8px}}
footer{{color:var(--muted); font-size:11px; text-align:center; padding:16px; font-family: ui-monospace, monospace}}
.pill{{display:inline-flex; align-items:center; gap:5px; padding:5px 9px; border-radius:999px; background:#fffbeb; border:1px solid var(--border); font-size:11px; font-family: ui-monospace, monospace}}
</style>
</head>
<body>
<header>
  <h1><span style="color:var(--accent)">›_</span> AuDeep <span style="color:var(--muted); font-weight:400">::</span> AUDIT <span style="font-size:13px; background:#1c1917; color:#fdfbf7; padding:2px 6px; border-radius:6px; vertical-align:middle">v0.1.0</span></h1>
  <div class="sub">Generado: {} · Subred: {} · Hosts: {} · Vulns: {} · Duración: {:.1}s · <span class="pill">● Live</span> <span id="liveStatus" class="muted">offline</span> · <span class="muted">`audeep --serve 0.0.0.0:8766`</span></div>
</header>
<div class="wrap">
  <div class="stats">
    <div class="stat"><div class="num" style="color:#38bdf8">{}</div><div class="lbl">Hosts vivos</div></div>
    <div class="stat"><div class="num" style="color:#ef4444">{}</div><div class="lbl">Hallazgos</div></div>
    <div class="stat"><div class="num" style="color:#a78bfa">{}</div><div class="lbl">Vendors únicos</div></div>
    <div class="stat"><div class="num" style="color:#22c55e">{}</div><div class="lbl">Puertos distintos</div></div>
  </div>

  <div class="card" style="border-left:3px solid #1c1917">
    <h2>// Hardware — {}</h2>
    <p class="muted" style="margin:-4px 0 10px 0; font-size:11px; font-family: ui-monospace, monospace">Inventario local `sysinfo 0.30` + `Components` · CPU/Mem/Discos/IFaces/Sensores · Offline, sin agentes</p>
    <div class="grid">
      <div class="kv"><div class="k">Sistema</div><div class="v">{} {}<br><small>{}</small></div></div>
      <div class="kv"><div class="k">CPU</div><div class="v">{}<br><small>{} núcleos físicos / {} lógicos @ {} MHz · {}</small></div></div>
      <div class="kv"><div class="k">Memoria</div><div class="v">{:.1} / {:.1} GB<br><small>{:.1} GB disponible</small></div></div>
      <div class="kv"><div class="k">Uptime / Carga</div><div class="v">{} s<br><small>{:.2} {:.2} {:.2} · {} sensores</small></div></div>
    </div>
  </div>

  <div class="charts">
    <div class="chartBox"><h3>Vendors Top</h3><canvas id="cVendor" class="canv" width="400" height="200"></canvas><div id="legendVendor" class="muted" style="font-size:11px; margin-top:6px"></div></div>
    <div class="chartBox"><h3>Severidad Vulns</h3><canvas id="cSev" class="canv" width="220" height="220"></canvas><div style="display:flex; gap:6px; margin-top:8px; flex-wrap:wrap"><span class="badge bCrit">Crítica {}</span><span class="badge bAlta">Alta {}</span><span class="badge bMedia">Media {}</span><span class="badge bBaja">Baja {}</span></div></div>
    <div class="chartBox"><h3>Puertos Top</h3><canvas id="cPorts" class="canv" width="400" height="200"></canvas></div>
  </div>

  <div class="card">
    <h2>// Almacenamiento</h2>
    <p class="muted" style="margin:-4px 0 10px 0; font-size:11px; font-family: ui-monospace, monospace">`Disks::new_with_refreshed_list()` · GB = 1024³ · Tipo fijo/extraíble</p>
    <table><thead><tr><th>Nombre</th><th>Punto</th><th>FS</th><th>Espacio</th><th>Tipo</th></tr></thead><tbody>{}</tbody></table>
  </div>

  <div class="card">
    <h2>// Interfaces locales · Sensores</h2>
    <p class="muted" style="margin:-4px 0 10px 0; font-size:11px; font-family: ui-monospace, monospace">`Networks` MAC + `Components` temp · `load_avg` 1/5/15m · Normal vacío en Windows/VM</p>
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px">
      <div><table><thead><tr><th>Interfaz</th><th>MAC</th></tr></thead><tbody>{}</tbody></table></div>
      <div><table><thead><tr><th>Etiqueta</th><th>Temp</th><th>Máx</th><th>Crítica</th></tr></thead><tbody>{}</tbody></table></div>
    </div>
  </div>

  <div class="card" style="border-left:3px solid #dc2626">
    <h2>// Red — {} vivos · {} hallazgos <span class="muted" style="font-weight:400">· OUI {} · cve.db {}</span></h2>
    <p class="muted" style="margin:-4px 0 10px 0; font-size:11px; font-family: ui-monospace, monospace">Descubrimiento `/24` UDP trick + TCP 80/445/22/53 + `ping` + `arp -a` + OUI 40k + reverse DNS + `mdns-sd` + `SSDP` M-SEARCH · `COMMON_PORTS 21` + banner 800ms + `cve.db` SQLite offline</p>
    <div class="controls">
      <input id="q" placeholder="🔍 Buscar IP, hostname, MAC, vendor, mDNS, SSDP, puerto...">
      <select id="fSev"><option value="">Todas severidades</option><option value="critica">Crítica</option><option value="alta">Alta</option><option value="media">Media</option><option value="baja">Baja</option><option value="sano">Sanos (0 vulns)</option></select>
      <select id="fVendor"><option value="">Todos vendors</option></select>
      <button class="btn" onclick="exportJson()">⬇ JSON</button>
      <button class="btn" onclick="window.print()">🖨 Print</button>
    </div>
    <div style="overflow:auto; max-height:520px; border:1px solid var(--border); border-radius:12px">
    <table id="tbl"><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Lat</th><th>Puertos</th><th>Vulns</th><th>mDNS</th><th>SSDP</th></tr></thead><tbody>{}</tbody></table>
    </div>
    <p class="muted" style="margin-top:10px; font-size:11px">Puertos escaneados: {} · mDNS/SSDP 1.2s · Doble click fila para copiar IP · <span id="filteredCount"></span></p>
  </div>
</div>
<footer>AuDeep v0.1.0 · Rust · Offline-first · <span id="footTime"></span> · Hecho con 🦀</footer>
"#,
        self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        html_escape(&subnet),
        self.network.total_hosts_alive,
        self.network.total_vulnerabilities,
        self.network.scan_duration_secs,
        self.network.total_hosts_alive,
        self.network.total_vulnerabilities,
        vendor_sorted.len(),
        port_sorted.len(),
        html_escape(&self.hardware.hostname),
        html_escape(&self.hardware.os_name),
        html_escape(&self.hardware.os_version),
        html_escape(&self.hardware.kernel_version),
        html_escape(&self.hardware.cpu.brand),
        self.hardware.cpu.cores_physical.unwrap_or(0),
        self.hardware.cpu.cores_logical,
        self.hardware.cpu.frequency_mhz,
        html_escape(&self.hardware.cpu.vendor),
        self.hardware.memory.used_gb,
        self.hardware.memory.total_gb,
        self.hardware.memory.available_gb,
        self.hardware.uptime_secs,
        self.hardware.load_avg_one,
        self.hardware.load_avg_five,
        self.hardware.load_avg_fifteen,
        self.hardware.sensors.len(),
        sev_crit, sev_alta, sev_media, sev_baja,
        disks_rows,
        net_ifaces,
        sensors_rows,
        self.hosts.len(),
        self.network.total_vulnerabilities,
        oui_count,
        cve_count,
        hosts_rows,
        crate::scanner::COMMON_PORTS.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        );

        // JS para Charts + Filtros + Live
        let js_template = r##"<script>
const HOSTS=__DATA__;
const VENDOR_LABELS="__VENDOR_LABELS__".split("|").filter(Boolean);
const VENDOR_VALS="__VENDOR_VALS__".split(",").filter(Boolean).map(Number);
const PORT_LABELS="__PORT_LABELS__".split(",").filter(Boolean);
const PORT_VALS="__PORT_VALS__".split(",").filter(Boolean).map(Number);
const SEV=[__SEV_CRIT__,__SEV_ALTA__,__SEV_MEDIA__,__SEV_BAJA__];
function drawBar(id, labels, vals, color){
  const c=document.getElementById(id); if(!c) return; const ctx=c.getContext('2d'); const W=c.width, H=c.height, pad=28;
  ctx.clearRect(0,0,W,H); if(!vals.length){ ctx.fillStyle="#78716c"; ctx.font="12px ui-monospace, monospace"; ctx.fillText("sin datos", 10, H/2); return;}
  const max=Math.max(...vals,1); const bw=(W-pad*2)/vals.length*0.62; const gap=(W-pad*2)/vals.length*0.38;
  labels.forEach((lb,i)=>{ const x=pad + i*(bw+gap) + gap/2; const h=(vals[i]/max)*(H-pad*2-14); const y=H-pad - h;
    const grad=ctx.createLinearGradient(x,y,x,y+h); grad.addColorStop(0, color); grad.addColorStop(1, "#fdfbf7");
    ctx.fillStyle=grad; ctx.beginPath(); if(ctx.roundRect) ctx.roundRect(x,y,bw,h,6); else ctx.rect(x,y,bw,h); ctx.fill();
    ctx.fillStyle="#1c1917"; ctx.font="10px ui-monospace, monospace"; ctx.textAlign="center"; ctx.fillText(String(vals[i]), x+bw/2, y-4);
    ctx.fillStyle="#57534e"; ctx.font="9px ui-monospace, monospace"; let s=lb.length>14?lb.slice(0,13)+"…":lb; ctx.fillText(s, x+bw/2, H-6);
  });
}
function drawPie(id, vals, colors){
  const c=document.getElementById(id); if(!c) return; const ctx=c.getContext('2d'); const W=c.width, H=c.height; const cx=W/2, cy=H/2, r=Math.min(W,H)/2 -14;
  ctx.clearRect(0,0,W,H); const total=vals.reduce((a,b)=>a+b,0); if(total===0){ ctx.fillStyle="#78716c"; ctx.font="12px ui-monospace, monospace"; ctx.textAlign="center"; ctx.fillText("0 hallazgos", cx, cy); return;}
  let ang=-Math.PI/2; vals.forEach((v,i)=>{ const slice= v/total* Math.PI*2; ctx.beginPath(); ctx.moveTo(cx,cy); ctx.arc(cx,cy,r,ang, ang+slice); ctx.closePath(); ctx.fillStyle=colors[i]; ctx.fill(); ang+=slice; });
  ctx.beginPath(); ctx.arc(cx,cy,r*0.58,0,Math.PI*2); ctx.fillStyle="#ffffff"; ctx.fill(); ctx.strokeStyle="#e7e5e4"; ctx.lineWidth=1; ctx.stroke();
  ctx.fillStyle="#1c1917"; ctx.font="bold 16px ui-monospace, monospace"; ctx.textAlign="center"; ctx.fillText(String(total), cx, cy+5);
  ctx.fillStyle="#57534e"; ctx.font="9px ui-monospace, monospace"; ctx.fillText("vulns", cx, cy+18);
}
drawBar("cVendor", VENDOR_LABELS, VENDOR_VALS, "#38bdf8");
drawBar("cPorts", PORT_LABELS, PORT_VALS, "#818cf8");
drawPie("cSev", SEV, ["#ef4444","#f59e0b","#eab308","#22c55e"]);
{
  const sel=document.getElementById("fVendor");
  VENDOR_LABELS.forEach(v=>{ const o=document.createElement("option"); o.value=v.toLowerCase(); o.textContent=v; sel.appendChild(o); });
}
const q=document.getElementById("q"), fSev=document.getElementById("fSev"), fVendor=document.getElementById("fVendor"), tbl=document.getElementById("tbl");
function apply(){
  const qq=q.value.toLowerCase(), fs=fSev.value, fv=fVendor.value; let vis=0;
  tbl.querySelectorAll("tbody tr").forEach(tr=>{
    const txt=tr.innerText.toLowerCase();
    const sev=tr.getAttribute("data-sev")||""; const vendor=tr.getAttribute("data-vendor")||"";
    let ok= (!qq || txt.includes(qq)) && (!fv || vendor.includes(fv));
    if(fs==="sano") ok= ok && !sev;
    else if(fs) ok= ok && sev.includes(fs);
    tr.style.display= ok? "":"none"; if(ok) vis++;
  });
  document.getElementById("filteredCount").textContent= vis + " / " + HOSTS.length + " visibles";
  document.getElementById("footTime").textContent= new Date().toLocaleString();
}
q.addEventListener("input", apply); fSev.addEventListener("change", apply); fVendor.addEventListener("change", apply);
tbl.addEventListener("dblclick", e=>{ const tr=e.target.closest("tr"); if(tr){ const ip=tr.children[0]?.innerText; if(ip){ navigator.clipboard?.writeText(ip); tr.style.background="rgba(56,189,248,0.15)"; setTimeout(()=>tr.style.background="",600);} }});
function exportJson(){ const blob=new Blob([JSON.stringify({generated:new Date().toISOString(), hosts:HOSTS}, null,2)], {type:"application/json"}); const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download="audeep_export.json"; a.click(); }
// Live poll si está servido via http
(function live(){
  const isHttp=location.protocol.startsWith("http");
  const el=document.getElementById("liveStatus");
  if(isHttp){ el.textContent="live polling /json cada 5s"; el.style.color="#22c55e";
    setInterval(async()=>{ try{ const r=await fetch("/json",{cache:"no-store"}); if(r.ok){ const j=await r.json(); el.textContent="live " + new Date().toLocaleTimeString() + " ("+ (j.hosts?.length||0) +" hosts)"; }}catch(e){} },5000);
  } else { el.textContent="offline file://"; }
})();
// Vendor legend
document.getElementById("legendVendor").textContent= VENDOR_LABELS.map((l,i)=> l + " ("+ (VENDOR_VALS[i]||0) +")").join(" · ");
apply();
</script>
</body>
</html>
"##;
        let js = js_template
            .replace("__DATA__", &data_json_escaped)
            .replace("__VENDOR_LABELS__", &vendor_labels)
            .replace("__VENDOR_VALS__", &vendor_vals)
            .replace("__PORT_LABELS__", &port_labels)
            .replace("__PORT_VALS__", &port_vals)
            .replace("__SEV_CRIT__", &sev_crit.to_string())
            .replace("__SEV_ALTA__", &sev_alta.to_string())
            .replace("__SEV_MEDIA__", &sev_media.to_string())
            .replace("__SEV_BAJA__", &sev_baja.to_string());

        let mut html = base;
        html.push_str(&js);
        html
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
