mod hardware;
mod network;
mod report;
mod scanner;
mod serve;
mod vuln;

use std::path::PathBuf;
use std::time::Instant;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Modo servidor para AP: --serve 0.0.0.0:80, --serve=192.168.4.1:80, o --serve 192.168.4.1:80
    let serve_addr = {
        let mut addr: Option<String> = None;
        for (i, a) in args.iter().enumerate() {
            if a == "--serve" {
                // --serve ADDR como dos args
                if let Some(next) = args.get(i + 1) {
                    if !next.starts_with("--") {
                        addr = Some(next.clone());
                        break;
                    }
                }
                addr = Some("0.0.0.0:8080".to_string());
                break;
            } else if a.starts_with("--serve=") {
                addr = Some(a.split('=').nth(1).unwrap_or("0.0.0.0:8080").to_string());
                break;
            }
        }
        addr
    };
    if let Some(addr) = serve_addr {
        if let Err(e) = serve::serve(&addr).await {
            eprintln!("Error serve: {}", e);
        }
        return;
    }

    let do_scan = !args.contains(&"--no-scan".to_string());
    let out_json = args.iter().find_map(|a| {
        if a.starts_with("--json=") {
            Some(PathBuf::from(a.trim_start_matches("--json=")))
        } else {
            None
        }
    });
    let out_html = args.iter().find_map(|a| {
        if a.starts_with("--html=") {
            Some(PathBuf::from(a.trim_start_matches("--html=")))
        } else {
            None
        }
    });

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
                println!(
                    "  - {} {} | MAC {} | vendor {} | {} ms | puertos: {}{}",
                    h.ip,
                    h.hostname.clone().unwrap_or_default(),
                    h.mac.clone().unwrap_or_else(|| "-".to_string()),
                    h.vendor.clone().unwrap_or_else(|| "-".to_string()),
                    h.latency_ms.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                    ports,
                    vuln_str
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
