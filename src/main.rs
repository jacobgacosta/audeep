mod hardware;
mod network;
mod report;
mod scanner;
mod serve;
mod vuln;

use clap::Parser;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name="audeep", version, about="AuDeep — Auditor de Hardware y Red (Rust)", long_about=None)]
struct Args {
    /// No escanear red, solo hardware local
    #[arg(long)]
    no_scan: bool,

    /// Ruta JSON de salida (ej. --json=out.json)
    #[arg(long, value_name="PATH")]
    json: Option<PathBuf>,

    /// Ruta HTML de salida (ej. --html=out.html)
    #[arg(long, value_name="PATH")]
    html: Option<PathBuf>,

    /// Modo servidor: expone / (HTML), /json, /health en ADDR (default 0.0.0.0:8766, evita Koupper 8080)
    /// Uso: --serve, --serve 192.168.4.1:80, --serve=192.168.4.1:80
    #[arg(long, value_name="ADDR", num_args=0..=1, default_missing_value="0.0.0.0:8766")]
    serve: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Some(addr) = args.serve {
        if let Err(e) = serve::serve(&addr).await {
            eprintln!("Error serve: {}", e);
        }
        return;
    }

    let do_scan = !args.no_scan;
    let out_json = args.json;
    let out_html = args.html;

    println!("AuDeep — auditoría iniciada...");
    let hw = hardware::collect_hardware_info();
    println!(
        "Hardware: {} | {} {} | {} núcleos | {:.1}/{:.1} GB RAM",
        hw.hostname, hw.os_name, hw.os_version, hw.cpu.cores_logical, hw.memory.used_gb, hw.memory.total_gb
    );

    let subnet = network::local_subnet_cidr();
    if let Some(ref s) = subnet {
        println!("Subred detectada: {}", s);
    } else {
        println!("Subred no detectada (sin IP local). Solo se reportará hardware.");
    }

    let mut hosts = Vec::new();
    let mut duration_secs = 0.0;

    if do_scan {
        if subnet.is_some() {
            println!("Escaneando red local (puede tardar 20-60s, timeout 400ms, 64 tareas paralelas)...");
            let start = Instant::now();
            let mut discovered = network::discover_hosts(400, 64).await;
            discovered = network::enrich_with_arp(discovered).await;
            discovered = network::enrich_with_mdns_ssdp(discovered, 1200).await;
            duration_secs = start.elapsed().as_secs_f64();
            println!("Hosts vivos: {}", discovered.len());
            for h in &discovered {
                let ports = if h.open_ports.is_empty() {
                    "ninguno".to_string()
                } else {
                    h.open_ports
                        .iter()
                        .map(|p| format!("{}{}", p.port, p.service_hint.as_ref().map(|s| format!("({})", s)).unwrap_or_default()))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let vuln_str = if h.vulnerabilities.is_empty() {
                    "".to_string()
                } else {
                    format!(
                        " | vulns: {}",
                        h.vulnerabilities
                            .iter()
                            .map(|v| format!("{}({})", v.cve, v.severity))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                let mdns_str = if h.mdns_names.is_empty() { "".to_string() } else { format!(" | mdns: {}", h.mdns_names.join(",")) };
                let ssdp_str = h.ssdp_location.as_ref().map(|s| format!(" | ssdp: {}", s)).unwrap_or_default();
                println!(
                    "  - {} {} | MAC {} | vendor {} | {} ms | puertos: {}{}{}{}",
                    h.ip,
                    h.hostname.clone().unwrap_or_default(),
                    h.mac.clone().unwrap_or_else(|| "-".to_string()),
                    h.vendor.clone().unwrap_or_else(|| "-".to_string()),
                    h.latency_ms.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                    ports,
                    vuln_str,
                    mdns_str,
                    ssdp_str
                );
            }
            hosts = discovered;
        } else {
            // sin subred, escanear solo localhost
            println!("Sin subred, escaneando localhost...");
            let start = Instant::now();
            let local_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
            let open = scanner::scan_common_ports(local_ip, 400).await;
            let vulns = vuln::check_host(&open);
            duration_secs = start.elapsed().as_secs_f64();
            hosts.push(network::HostInfo {
                ip: "127.0.0.1".to_string(),
                hostname: Some(hw.hostname.clone()),
                mac: None,
                vendor: None,
                is_alive: true,
                open_ports: open,
                latency_ms: Some(0),
                vulnerabilities: vulns,
                mdns_names: Vec::new(),
                ssdp_location: None,
            });
        }
    } else {
        println!("--no-scan activo: se omite descubrimiento de red.");
    }

    let audit = report::AuditReport::new(hw, hosts, subnet, duration_secs);

    // Salida JSON a stdout (siempre)
    match audit.to_json_pretty() {
        Ok(json) => {
            println!("\n=== JSON ===\n{}", json);
        }
        Err(e) => eprintln!("Error JSON: {}", e),
    }

    // Guardar a disco si se pidió
    if let Some(ref p) = out_json {
        if let Err(e) = audit.save_json(p) {
            eprintln!("Error guardando JSON en {:?}: {}", p, e);
        } else {
            println!("JSON guardado en {:?}", p);
        }
    }
    if let Some(ref p) = out_html {
        if let Err(e) = audit.save_html(p) {
            eprintln!("Error guardando HTML en {:?}: {}", p, e);
        } else {
            println!("HTML guardado en {:?}", p);
        }
    }

    // Por defecto, si no se pasó --json/--html, guardar en cwd
    if out_json.is_none() && out_html.is_none() {
        let default_json = PathBuf::from("audeep_reporte.json");
        let default_html = PathBuf::from("audeep_reporte.html");
        let _ = audit.save_json(&default_json);
        let _ = audit.save_html(&default_html);
        println!("\nReportes por defecto: {:?} y {:?}", default_json, default_html);
    }
}
