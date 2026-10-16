use crate::hardware::HardwareReport;
use crate::history::Event;
use crate::network::HostInfo;
use crate::risk;
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
    /// Cambios y anomalias contra el escaneo anterior (vacio si no hay historial).
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkSummary {
    pub local_subnet: Option<String>,
    pub total_hosts_alive: usize,
    pub scan_duration_secs: f64,
    pub total_vulnerabilities: usize,
    /// Hosts con score de riesgo critico.
    pub critical_hosts: usize,
}

impl AuditReport {
    pub fn new(
        hardware: HardwareReport,
        hosts: Vec<HostInfo>,
        local_subnet: Option<String>,
        duration_secs: f64,
    ) -> Self {
        let total = hosts.len();
        let total_vulns = hosts.iter().map(|h| h.vulnerabilities.len()).sum();
        let critical_hosts = hosts
            .iter()
            .filter(|h| risk::score_host(h).level == "critico")
            .count();
        Self {
            generated_at: Utc::now(),
            hardware,
            network: NetworkSummary {
                local_subnet,
                total_hosts_alive: total,
                scan_duration_secs: duration_secs,
                total_vulnerabilities: total_vulns,
                critical_hosts,
            },
            hosts,
            events: Vec::new(),
        }
    }

    /// Adjunta los eventos del historial (diff contra el escaneo anterior).
    pub fn with_events(mut self, events: Vec<Event>) -> Self {
        self.events = events;
        self
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn save_json(&self, path: &Path) -> std::io::Result<()> {
        let json = self.to_json_pretty().unwrap_or_else(|_| "{}".to_string());
        fs::write(path, json)
    }

    pub fn save_html(&self, path: &Path) -> std::io::Result<()> {
        fs::write(path, self.to_html())
    }

    pub fn to_html(&self) -> String {
        let mut ordenados: Vec<(&HostInfo, risk::RiskScore)> = self
            .hosts
            .iter()
            .map(|h| (h, risk::score_host(h)))
            .collect();
        ordenados.sort_by(|a, b| b.1.score.cmp(&a.1.score).then(a.0.ip.cmp(&b.0.ip)));

        let filas: String = ordenados.iter().map(|(h, r)| fila_host(h, r)).collect();
        let eventos = self.eventos_html();
        let subnet = self
            .network
            .local_subnet
            .clone()
            .unwrap_or_else(|| "no detectada".to_string());
        let cve_count = crate::vuln::load_db().len();
        let oui_count = crate::network::oui_count();
        let puertos = crate::scanner::active_ports()
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let data_json = serde_json::to_string(&self.hosts).unwrap_or_else(|_| "[]".to_string());
        let jsonl = self
            .hosts
            .iter()
            .filter_map(|h| serde_json::to_string(h).ok())
            .collect::<Vec<_>>()
            .join("\n");
        let (vendors, puertos_top, sev) = self.graficos();
        let hw = &self.hardware;

        let mut s = String::with_capacity(96 * 1024);
        s.push_str(&format!(
            r##"<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuDeep — Reporte de auditoría</title>
<style>
:root{{--bg:#fdfbf7;--fg:#1c1917;--muted:#78716c;--card:#fff;--border:#e7e5e4;--accent:#0ea5e9;--crit:#dc2626;--alta:#d97706;--media:#ca8a04;--baja:#16a34a}}
*{{box-sizing:border-box}} body{{margin:0;font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}}
header{{padding:22px 20px 14px;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10;backdrop-filter:blur(8px);background:rgba(253,251,247,.93)}}
h1{{margin:0;font-size:21px;font-weight:800;font-family:ui-monospace,monospace}} .sub{{color:var(--muted);font-size:12px;margin-top:4px;font-family:ui-monospace,monospace}}
.wrap{{max-width:1280px;margin:0 auto;padding:18px}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:16px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.05)}}
.card h2{{margin:0 0 10px;font-size:12px;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);font-family:ui-monospace,monospace}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px}} @media(max-width:900px){{.stats{{grid-template-columns:repeat(2,1fr)}}}}
.stat{{background:#fff;border:1px solid var(--border);border-radius:14px;padding:12px;text-align:center}} .stat .num{{font-size:24px;font-weight:800;font-family:ui-monospace,monospace}} .stat .lbl{{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.6px}}
.grid{{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}}
.kv{{background:#fff;border:1px solid var(--border);border-radius:12px;padding:12px}} .kv .k{{color:var(--muted);font-size:10px;text-transform:uppercase}} .kv .v{{font-weight:700;margin-top:4px}} .kv .v small{{font-weight:400;color:var(--muted);font-size:11px;font-family:ui-monospace,monospace}}
table{{width:100%;border-collapse:collapse;font-size:12px}} th,td{{text-align:left;padding:8px;border-bottom:1px solid var(--border);vertical-align:top;font-family:ui-monospace,monospace;font-size:11px}} th{{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.6px;background:#fffbeb}}
.tag{{display:inline-block;background:#fff;border:1px solid var(--border);border-radius:6px;padding:2px 6px;margin:2px 2px 0 0;font-size:11px}}
.muted{{color:var(--muted)}} .badge{{display:inline-block;padding:2px 7px;border-radius:999px;font-size:10px;font-weight:700;border:1px solid transparent}}
.bCrit{{background:#fef2f2;color:#991b1b;border-color:#fecaca}} .bAlta{{background:#fffbeb;color:#92400e;border-color:#fde68a}} .bMedia{{background:#fefce8;color:#854d0e;border-color:#fde047}} .bBaja{{background:#f0fdf4;color:#166534;border-color:#bbf7d0}}
.bConf{{background:#ecfdf5;color:#065f46;border-color:#a7f3d0}} .bProb{{background:#eff6ff;color:#1e40af;border-color:#bfdbfe}} .bSosp{{background:#f8fafc;color:#475569;border-color:#e2e8f0}}
.risk{{font-weight:800;font-family:ui-monospace,monospace}} .rCrit{{color:#b91c1c}} .rAlto{{color:#c2410c}} .rMedio{{color:#a16207}} .rBajo{{color:#15803d}}
.controls{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}} .controls input,.controls select{{flex:1;min-width:150px;padding:8px 10px;border-radius:8px;border:1px solid var(--border);background:#fff;font-family:ui-monospace,monospace;font-size:12px}}
.btn{{padding:8px 12px;border-radius:8px;border:1px solid var(--border);background:#1c1917;color:#fdfbf7;cursor:pointer;font-weight:600;font-family:ui-monospace,monospace;font-size:12px}}
.charts{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px}} @media(max-width:900px){{.charts{{grid-template-columns:1fr}}}}
.chartBox{{background:#fff;border:1px solid var(--border);border-radius:14px;padding:14px}} .canv{{width:100%;height:auto;display:block}} #cVendor,#cPorts{{aspect-ratio:2/1}} #cSev{{aspect-ratio:1/1;max-width:200px;margin:0 auto}}
table.ev{{font-size:11px}} .evN{{color:#0369a1;font-weight:700}} .evD{{color:#b91c1c;font-weight:700}} .evP{{color:#a16207;font-weight:700}} .evA{{color:#7c2d12;font-weight:700}}
footer{{color:var(--muted);font-size:11px;text-align:center;padding:16px;font-family:ui-monospace,monospace}}
</style>
</head>
<body>
<header>
  <h1><span style="color:var(--accent)">›_</span> AuDeep <span class="muted">::</span> AUDIT <span style="font-size:12px;background:#1c1917;color:#fdfbf7;padding:2px 6px;border-radius:6px">v0.2</span></h1>
  <div class="sub">Generado {gen} · Subred {subnet} · Hosts {hosts} · Hallazgos {vulns} · Duración {dur:.1}s · <span id="live" class="muted">offline</span></div>
</header>
<div class="wrap">
  <div class="stats">
    <div class="stat"><div class="num" style="color:#0284c7">{hosts}</div><div class="lbl">Hosts vivos</div></div>
    <div class="stat"><div class="num" style="color:#dc2626">{vulns}</div><div class="lbl">Hallazgos</div></div>
    <div class="stat"><div class="num" style="color:#b91c1c">{criticos}</div><div class="lbl">Hosts críticos</div></div>
    <div class="stat"><div class="num" style="color:#7c3aed">{nvendors}</div><div class="lbl">Vendors</div></div>
    <div class="stat"><div class="num" style="color:#16a34a">{npuertos}</div><div class="lbl">Puertos</div></div>
  </div>
"##,
            gen = self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            subnet = escape(&subnet),
            hosts = self.hosts.len(),
            vulns = self.network.total_vulnerabilities,
            dur = self.network.scan_duration_secs,
            criticos = self.network.critical_hosts,
            nvendors = vendors.len(),
            npuertos = puertos_top.len(),
        ));

        s.push_str(&eventos);

        s.push_str(&format!(
            r##"  <div class="card">
    <h2>// Hardware — {hostname}</h2>
    <div class="grid">
      <div class="kv"><div class="k">Sistema</div><div class="v">{os} {osv}<br><small>kernel {kernel} · uptime {uptime}s</small></div></div>
      <div class="kv"><div class="k">CPU</div><div class="v">{cpu}<br><small>{fis} físicos / {log} lógicos @ {mhz} MHz · {ven}</small></div></div>
      <div class="kv"><div class="k">Memoria</div><div class="v">{used:.1} / {total:.1} GB<br><small>{avail:.1} GB disponible</small></div></div>
      <div class="kv"><div class="k">Carga 1/5/15 · Sensores</div><div class="v">{l1:.2} {l5:.2} {l15:.2}<br><small>{nsens} sensores</small></div></div>
    </div>
  </div>

  <div class="card">
    <h2>// Almacenamiento e interfaces</h2>
    <table><thead><tr><th>Disco</th><th>Punto</th><th>FS</th><th>Libre / Total</th><th>Tipo</th></tr></thead><tbody>{discos}</tbody></table>
    <table style="margin-top:10px"><thead><tr><th>Interfaz</th><th>MAC</th><th>IPs</th></tr></thead><tbody>{ifaces}</tbody></table>
  </div>

  <div class="charts">
    <div class="chartBox"><h3 style="font-size:11px;color:var(--muted)">Vendors top</h3><canvas id="cVendor" class="canv" width="400" height="200"></canvas><div id="leg" class="muted" style="font-size:11px"></div></div>
    <div class="chartBox"><h3 style="font-size:11px;color:var(--muted)">Severidad</h3><canvas id="cSev" class="canv" width="220" height="220"></canvas><div style="margin-top:8px"><span class="badge bCrit">Crítica {sc}</span> <span class="badge bAlta">Alta {sa}</span> <span class="badge bMedia">Media {sm}</span> <span class="badge bBaja">Baja {sb}</span></div></div>
    <div class="chartBox"><h3 style="font-size:11px;color:var(--muted)">Puertos top</h3><canvas id="cPorts" class="canv" width="400" height="200"></canvas></div>
  </div>

  <div class="card" style="border-left:3px solid #dc2626">
    <h2>// Red — {hosts} vivos · {vulns} hallazgos <span class="muted" style="font-weight:400">· OUI {oui} · reglas {cves} · puertos: {puertos}</span></h2>
    <p class="muted" style="font-size:11px;font-family:ui-monospace,monospace">Ordenado por riesgo · la columna Riesgo muestra score y motivo · cada hallazgo dice su confianza y con qué se sostiene</p>
    <div class="controls">
      <input id="q" placeholder="Buscar IP, hostname, MAC, vendor, mDNS, SSDP, puerto, CVE...">
      <select id="fRiesgo"><option value="">Todo riesgo</option><option value="critico">Crítico</option><option value="alto">Alto</option><option value="medio">Medio</option><option value="bajo">Bajo</option><option value="sin">Sin riesgo</option></select>
      <select id="fSev"><option value="">Toda severidad</option><option value="critica">Crítica</option><option value="alta">Alta</option><option value="media">Media</option><option value="baja">Baja</option><option value="sano">Sin hallazgos</option></select>
      <select id="fVendor"><option value="">Todos los vendors</option></select>
      <button class="btn" onclick="exportCsv()">⬇ CSV</button>
      <button class="btn" onclick="exportJsonl()">⬇ JSONL</button>
      <button class="btn" onclick="window.print()">🖨 Print</button>
    </div>
    <div style="overflow:auto;max-height:560px;border:1px solid var(--border);border-radius:12px">
      <table id="tbl"><thead><tr><th>IP</th><th>Host</th><th>MAC</th><th>Vendor (fuente)</th><th>Riesgo</th><th>Puertos</th><th>Hallazgos</th><th>mDNS / SSDP</th></tr></thead><tbody>{filas}</tbody></table>
    </div>
    <p class="muted" style="margin-top:10px;font-size:11px"><span id="cont"></span> · doble click en una fila copia la IP</p>
  </div>
</div>
<footer>AuDeep v0.2 · Rust · offline-first · sin CDN · <span id="ft"></span></footer>
"##,
            hostname = escape(&hw.hostname),
            os = escape(&hw.os_name),
            osv = escape(&hw.os_version),
            kernel = escape(&hw.kernel_version),
            uptime = hw.uptime_secs,
            cpu = escape(hw.cpu.brand.trim()),
            fis = hw.cpu.cores_physical.unwrap_or(0),
            log = hw.cpu.cores_logical,
            mhz = hw.cpu.frequency_mhz,
            ven = escape(&hw.cpu.vendor),
            used = hw.memory.used_gb,
            total = hw.memory.total_gb,
            avail = hw.memory.available_gb,
            l1 = hw.load_avg_one,
            l5 = hw.load_avg_five,
            l15 = hw.load_avg_fifteen,
            nsens = hw.sensors.len(),
            discos = self.discos_html(),
            ifaces = self.ifaces_html(),
            sc = sev.0,
            sa = sev.1,
            sm = sev.2,
            sb = sev.3,
            hosts = self.hosts.len(),
            vulns = self.network.total_vulnerabilities,
            oui = oui_count,
            cves = cve_count,
            puertos = escape(&puertos),
            filas = filas,
        ));

        s.push_str(&format!(
            r##"<script>
const HOSTS={data};
const JSONL={jsonl_escaped};
const VENDOR_LABELS="{vl}".split("|").filter(Boolean);
const VENDOR_VALS="{vv}".split(",").filter(Boolean).map(Number);
const PORT_LABELS="{pl}".split(",").filter(Boolean);
const PORT_VALS="{pv}".split(",").filter(Boolean).map(Number);
const SEV=[{sc},{sa},{sm},{sb}];
function bar(id,labels,vals,color){{
  const c=document.getElementById(id); if(!c)return; const x=c.getContext('2d'),W=c.width,H=c.height,pad=28;
  x.clearRect(0,0,W,H); if(!vals.length){{x.fillStyle="#78716c";x.font="12px ui-monospace";x.fillText("sin datos",10,H/2);return;}}
  const max=Math.max(...vals,1),bw=(W-pad*2)/vals.length*.62,gap=(W-pad*2)/vals.length*.38;
  labels.forEach((lb,i)=>{{const bx=pad+i*(bw+gap)+gap/2,h=(vals[i]/max)*(H-pad*2-14),y=H-pad-h;
    const g=x.createLinearGradient(bx,y,bx,y+h);g.addColorStop(0,color);g.addColorStop(1,"#fdfbf7");
    x.fillStyle=g;x.beginPath();if(x.roundRect)x.roundRect(bx,y,bw,h,6);else x.rect(bx,y,bw,h);x.fill();
    x.fillStyle="#1c1917";x.font="10px ui-monospace";x.textAlign="center";x.fillText(String(vals[i]),bx+bw/2,y-4);
    x.fillStyle="#57534e";x.fillText(lb.length>14?lb.slice(0,13)+"…":lb,bx+bw/2,H-6);}});
}}
function pie(id,vals,colors){{
  const c=document.getElementById(id); if(!c)return; const x=c.getContext('2d'),W=c.width,H=c.height,cx=W/2,cy=H/2,r=Math.min(W,H)/2-14;
  x.clearRect(0,0,W,H); const t=vals.reduce((a,b)=>a+b,0);
  if(!t){{x.fillStyle="#78716c";x.font="12px ui-monospace";x.textAlign="center";x.fillText("0 hallazgos",cx,cy);return;}}
  let a=-Math.PI/2; vals.forEach((v,i)=>{{const s=v/t*Math.PI*2;x.beginPath();x.moveTo(cx,cy);x.arc(cx,cy,r,a,a+s);x.closePath();x.fillStyle=colors[i];x.fill();a+=s;}});
  x.beginPath();x.arc(cx,cy,r*.58,0,Math.PI*2);x.fillStyle="#fff";x.fill();
  x.fillStyle="#1c1917";x.font="bold 16px ui-monospace";x.textAlign="center";x.fillText(String(t),cx,cy+5);
}}
bar("cVendor",VENDOR_LABELS,VENDOR_VALS,"#38bdf8"); bar("cPorts",PORT_LABELS,PORT_VALS,"#818cf8");
pie("cSev",SEV,["#ef4444","#f59e0b","#eab308","#22c55e"]);
document.getElementById("leg").textContent=VENDOR_LABELS.map((l,i)=>l+" ("+(VENDOR_VALS[i]||0)+")").join(" · ");
{{const sel=document.getElementById("fVendor");VENDOR_LABELS.forEach(v=>{{const o=document.createElement("option");o.value=v.toLowerCase();o.textContent=v;sel.appendChild(o);}});}}
const q=document.getElementById("q"),fR=document.getElementById("fRiesgo"),fS=document.getElementById("fSev"),fV=document.getElementById("fVendor"),tbl=document.getElementById("tbl");
function apply(){{
  const qq=q.value.toLowerCase(),fr=fR.value,fs=fS.value,fv=fV.value; let vis=0;
  tbl.querySelectorAll("tbody tr").forEach(tr=>{{
    const sev=tr.getAttribute("data-sev")||"",ven=tr.getAttribute("data-vendor")||"",rie=tr.getAttribute("data-risk")||"";
    let ok=(!qq||tr.innerText.toLowerCase().includes(qq))&&(!fv||ven.includes(fv))&&(!fr||rie===fr);
    if(fs==="sano")ok=ok&&!sev; else if(fs)ok=ok&&sev.includes(fs);
    tr.style.display=ok?"":"none"; if(ok)vis++;
  }});
  document.getElementById("cont").textContent=vis+" / "+HOSTS.length+" visibles";
  document.getElementById("ft").textContent=new Date().toLocaleString();
}}
q.addEventListener("input",apply);fR.addEventListener("change",apply);fS.addEventListener("change",apply);fV.addEventListener("change",apply);
tbl.addEventListener("dblclick",e=>{{const tr=e.target.closest("tr");if(tr){{const ip=tr.children[0].innerText;navigator.clipboard?.writeText(ip);tr.style.background="rgba(56,189,248,.15)";setTimeout(()=>tr.style.background="",600);}}}});
function dl(name,text,type){{const b=new Blob([text],{{type}});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=name;a.click();}}
function exportCsv(){{
  const cols=["ip","hostname","mac","vendor","vendor_source","is_alive","latency_ms","risk","ports","findings","mdns","ssdp"];
  const esc=v=>'"'+String(v??"").replace(/"/g,'""')+'"';
  const rows=HOSTS.map(h=>[h.ip,h.hostname,h.mac,h.vendor,h.vendor_source,h.is_alive,h.latency_ms,(h.open_ports||[]).map(p=>p.port).join(" "),(h.vulnerabilities||[]).map(v=>v.cve+"("+v.severity+"/"+v.confidence+")").join(" "),(h.mdns_names||[]).join(" "),h.ssdp_location].map(esc).join(","));
  dl("audeep_hosts.csv",[cols.join(",")].concat(rows).join("\n"),"text/csv");
}}
function exportJsonl(){{dl("audeep_hosts.jsonl",JSONL,"application/x-ndjson");}}
(function live(){{
  const el=document.getElementById("live");
  if(location.protocol.startsWith("http")){{ el.textContent="live /json"; el.style.color="#16a34a";
    setInterval(async()=>{{try{{const r=await fetch("/json",{{cache:"no-store"}});if(r.ok){{const j=await r.json();el.textContent="live "+new Date().toLocaleTimeString()+" ("+(j.hosts?.length||0)+" hosts)";}}}}catch(e){{}}}},5000);
  }} else {{ el.textContent="offline file://"; }}
}})();
apply();
</script>
</body>
</html>
"##,
            data = data_json.replace("</", "<\\/"),
            jsonl_escaped = serde_json::to_string(&jsonl).unwrap_or_else(|_| "\"\"".to_string()),
            vl = vendors.join("|"),
            vv = vendors_vals(&self.hosts),
            pl = puertos_top.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>().join(","),
            pv = puertos_top.iter().map(|(_, n)| n.to_string()).collect::<Vec<_>>().join(","),
            sc = sev.0,
            sa = sev.1,
            sm = sev.2,
            sb = sev.3,
        ));

        s
    }

    /// Filas de la tabla de eventos (cambios y anomalías).
    fn eventos_html(&self) -> String {
        if self.events.is_empty() {
            return String::new();
        }
        let filas: String = self
            .events
            .iter()
            .map(|e| {
                let clase = match e.kind.as_str() {
                    "nuevo" => "evN",
                    "desaparecido" => "evD",
                    "puerto_nuevo" => "evP",
                    _ => "evA",
                };
                format!(
                    "<tr><td class=\"{clase}\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape(&e.kind),
                    escape(&e.ip),
                    escape(e.mac.as_deref().unwrap_or("—")),
                    escape(&e.detail)
                )
            })
            .collect();
        format!(
            r##"  <div class="card" style="border-left:3px solid #d97706">
    <h2>// Cambios desde el último escaneo — {n}</h2>
    <div style="overflow:auto;max-height:260px"><table class="ev"><thead><tr><th>Tipo</th><th>IP</th><th>MAC</th><th>Detalle</th></tr></thead><tbody>{filas}</tbody></table></div>
  </div>
"##,
            n = self.events.len()
        )
    }

    fn discos_html(&self) -> String {
        self.hardware
            .disks
            .iter()
            .map(|d| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.1} / {:.1} GB</td><td>{}</td></tr>",
                    escape(&d.name),
                    escape(&d.mount_point),
                    escape(&d.file_system),
                    d.available_gb,
                    d.total_gb,
                    if d.is_removable { "extraíble" } else { "fijo" }
                )
            })
            .collect()
    }

    fn ifaces_html(&self) -> String {
        self.hardware
            .network_interfaces
            .iter()
            .map(|n| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape(&n.name),
                    escape(&n.mac),
                    escape(&n.ips.join(", "))
                )
            })
            .collect()
    }

    /// (vendors ordenados, puertos top, conteo por severidad)
    fn graficos(
        &self,
    ) -> (
        Vec<String>,
        Vec<(String, usize)>,
        (usize, usize, usize, usize),
    ) {
        let mut vendors: HashMap<String, usize> = HashMap::new();
        let mut puertos: HashMap<String, usize> = HashMap::new();
        let mut sev = HashMap::new();
        for h in &self.hosts {
            let v = h
                .vendor
                .clone()
                .unwrap_or_else(|| "Desconocido".to_string());
            *vendors.entry(v).or_insert(0) += 1;
            for p in &h.open_ports {
                *puertos.entry(p.port.to_string()).or_insert(0) += 1;
            }
            for v in &h.vulnerabilities {
                *sev.entry(v.severity.clone()).or_insert(0) += 1;
            }
        }
        let mut vs: Vec<_> = vendors.into_iter().collect();
        vs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        vs.truncate(6);
        let mut ps: Vec<_> = puertos.into_iter().collect();
        ps.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        ps.truncate(8);
        let get = |k: &str| sev.get(k).copied().unwrap_or(0);
        let conteo = (get("critica"), get("alta"), get("media"), get("baja"));
        (vs.into_iter().map(|(k, _)| k).collect(), ps, conteo)
    }
}

fn vendors_vals(hosts: &[HostInfo]) -> String {
    let mut vendors: HashMap<String, usize> = HashMap::new();
    for h in hosts {
        let v = h
            .vendor
            .clone()
            .unwrap_or_else(|| "Desconocido".to_string());
        *vendors.entry(v).or_insert(0) += 1;
    }
    let mut vs: Vec<_> = vendors.into_iter().collect();
    vs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    vs.truncate(6);
    vs.into_iter()
        .map(|(_, n)| n.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn fila_host(h: &HostInfo, r: &risk::RiskScore) -> String {
    let puertos = if h.open_ports.is_empty() {
        "<span class='muted'>ninguno (o filtrado)</span>".to_string()
    } else {
        h.open_ports
            .iter()
            .map(|p| {
                let svc = p
                    .service_hint
                    .as_deref()
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default();
                let banner = p
                    .banner
                    .as_deref()
                    .map(|b| format!("<br><small class='muted'>{}</small>", escape(trunc(b, 80))))
                    .unwrap_or_default();
                format!("<span class='tag'>{}{svc}{banner}</span>", p.port)
            })
            .collect::<Vec<_>>()
            .join(" ")
    };

    let hallazgos = if h.vulnerabilities.is_empty() {
        "<span class='muted'>0</span>".to_string()
    } else {
        h.vulnerabilities
            .iter()
            .map(|v| {
                let (borde, clase) = match v.severity.as_str() {
                    "critica" => ("#dc2626", "bCrit"),
                    "alta" => ("#d97706", "bAlta"),
                    "media" => ("#ca8a04", "bMedia"),
                    _ => ("#16a34a", "bBaja"),
                };
                let (conf_clase, conf_txt) = match v.confidence.as_str() {
                    "confirmado" => ("bConf", "confirmado"),
                    "probable" => ("bProb", "probable"),
                    _ => ("bSosp", "sospecha"),
                };
                let evidencia = v
                    .evidence
                    .as_deref()
                    .map(|e| format!("<br><small class='muted'>evidencia: {}</small>", escape(trunc(e, 120))))
                    .unwrap_or_default();
                format!(
                    "<span style=\"display:inline-block;margin:2px;padding:4px 7px;background:#fff;border:1px solid #e7e5e4;border-left:3px solid {borde};border-radius:6px;font-size:11px\"><b>{}</b> <span class=\"badge {clase}\">{}</span> <span class=\"badge {conf_clase}\">{conf_txt}</span> :{}<br><small class='muted'>{}</small>{evidencia}</span>",
                    escape(&v.cve),
                    escape(&v.severity),
                    v.port,
                    escape(trunc(&v.description, 150)),
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };

    let extra = {
        let mut partes: Vec<String> = Vec::new();
        if !h.mdns_names.is_empty() {
            partes.push(format!("mDNS: {}", escape(&h.mdns_names.join(", "))));
        }
        if let Some(s) = h.ssdp_location.as_deref() {
            partes.push(format!("SSDP: {}", escape(trunc(s, 60))));
        }
        if partes.is_empty() {
            "—".to_string()
        } else {
            partes.join("<br>")
        }
    };

    let sev = h
        .vulnerabilities
        .iter()
        .map(|v| v.severity.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let vendor = h.vendor.clone().unwrap_or_else(|| "—".to_string());
    let fuente = h
        .vendor_source
        .as_deref()
        .map(|s| format!(" <small class='muted'>({})</small>", escape(s)))
        .unwrap_or_default();
    let rclase = match r.level {
        "critico" => "rCrit",
        "alto" => "rAlto",
        "medio" => "rMedio",
        _ => "rBajo",
    };
    // Clave del filtro JS: el nivel visible puede traer espacio ("sin riesgo"),
    // el atributo va sin espacio para que el `select` matchee exacto.
    let risk_key = match r.level {
        "critico" => "critico",
        "alto" => "alto",
        "medio" => "medio",
        "bajo" => "bajo",
        _ => "sin",
    };
    let motivos = if r.reasons.is_empty() {
        String::new()
    } else {
        format!(
            "<br><small class='muted'>{}</small>",
            escape(trunc(&r.reasons.join("; "), 90))
        )
    };

    format!(
        "<tr data-ip='{ip}' data-sev='{sev}' data-vendor='{ven}' data-risk='{risk}'><td>{ip}</td><td>{host}</td><td>{mac}</td><td>{vendor}{fuente}</td><td class='risk {rclase}'>{score} {level}{motivos}</td><td>{puertos}</td><td>{hallazgos}</td><td>{extra}</td></tr>",
        ip = escape(&h.ip),
        sev = sev,
        ven = escape(&vendor.to_lowercase()),
        risk = risk_key,
        host = escape(h.hostname.as_deref().unwrap_or("—")),
        mac = escape(h.mac.as_deref().unwrap_or("—")),
        score = r.score,
        level = escape(r.level),
    )
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Escapa HTML. Acepta `&str` o `String` (hay call sites con `trunc()`).
fn escape(s: impl AsRef<str>) -> String {
    let s = s.as_ref();
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware;
    use crate::scanner::PortResult;
    use crate::vuln::Finding;

    fn host(ip: &str, ports: &[u16], vulns: Vec<Finding>) -> HostInfo {
        HostInfo {
            ip: ip.to_string(),
            hostname: Some(format!("host-{ip}")),
            mac: Some("24:a6:5e:00:00:01".to_string()),
            vendor: Some("Tenda".to_string()),
            vendor_source: Some("oui".to_string()),
            is_alive: true,
            open_ports: ports
                .into_iter()
                .map(|p| PortResult {
                    port: *p,
                    state: "open".to_string(),
                    banner: None,
                    service_hint: Some("test".to_string()),
                })
                .collect(),
            latency_ms: Some(3),
            vulnerabilities: vulns,
            mdns_names: Vec::new(),
            ssdp_location: None,
        }
    }

    fn finding(cve: &str, sev: &str, conf: &str) -> Finding {
        Finding {
            cve: cve.to_string(),
            severity: sev.to_string(),
            port: 445,
            service: "SMB".to_string(),
            banner: Some("SMB1 habilitado".to_string()),
            confidence: conf.to_string(),
            evidence: Some("negociacion SMB real: SMB1 habilitado".to_string()),
            description: "desc".to_string(),
            recommendation: "rec".to_string(),
        }
    }

    fn reporte(hosts: Vec<HostInfo>, events: Vec<Event>) -> AuditReport {
        AuditReport::new(
            hardware::collect_hardware_info(),
            hosts,
            Some("192.168.1.0/24".to_string()),
            1.5,
        )
        .with_events(events)
    }

    #[test]
    fn html_has_rows_risk_confidence_and_evidence() {
        let r = reporte(
            vec![
                host(
                    "192.168.1.10",
                    &[445, 3389],
                    vec![finding("CVE-2017-0144", "critica", "confirmado")],
                ),
                host("192.168.1.11", &[], vec![]),
            ],
            Vec::new(),
        );
        let html = r.to_html();
        assert!(html.contains("192.168.1.10"));
        assert!(
            html.contains("data-risk='critico'"),
            "el host con critica confirmada es critico"
        );
        assert!(html.contains("confirmado"));
        assert!(html.contains("evidencia: negociacion SMB"));
        assert!(html.contains("exportCsv"));
        assert!(
            html.contains("data-risk='sin"),
            "el host limpio queda sin riesgo"
        );
        assert!(r.network.critical_hosts >= 1);
    }

    #[test]
    fn events_banner_only_when_there_are_events() {
        let sin = reporte(vec![host("192.168.1.10", &[], vec![])], Vec::new()).to_html();
        assert!(!sin.contains("Cambios desde el último escaneo"));

        let con = reporte(
            vec![host("192.168.1.10", &[], vec![])],
            vec![Event {
                kind: "nuevo".to_string(),
                ip: "192.168.1.99".to_string(),
                mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
                detail: "dispositivo nuevo".to_string(),
            }],
        )
        .to_html();
        assert!(con.contains("Cambios desde el último escaneo"));
        assert!(con.contains("192.168.1.99"));
        assert!(con.contains("dispositivo nuevo"));
    }

    #[test]
    fn json_roundtrip_keeps_new_fields() {
        let r = reporte(
            vec![host(
                "192.168.1.10",
                &[445],
                vec![finding("CVE-2017-0144", "critica", "confirmado")],
            )],
            Vec::new(),
        );
        let json = r.to_json_pretty().unwrap();
        assert!(json.contains("\"confidence\""));
        assert!(json.contains("\"evidence\""));
        assert!(json.contains("\"vendor_source\""));
        assert!(json.contains("\"events\""));
        assert!(json.contains("\"critical_hosts\""));
    }

    #[test]
    fn escaping_and_truncation_are_safe() {
        assert_eq!(
            escape("<b>&\"x\"</b>"),
            "&lt;b&gt;&amp;&quot;x&quot;&lt;/b&gt;"
        );
        assert_eq!(trunc("abcdef", 4), "abc…");
        assert_eq!(trunc("ab", 4), "ab");
    }
}
