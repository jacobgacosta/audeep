use crate::{hardware, network, report};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn serve(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("AuDeep serve en http://{}  (Ctrl+C para salir)", addr);
    println!("Endpoints: /  -> HTML (mamón), /json -> JSON, /health -> ok (scan cache 12s)");

    // Cache simple: (Instant, json, html)
    let cache: std::sync::Arc<tokio::sync::Mutex<Option<(Instant, String, String)>>> = std::sync::Arc::new(tokio::sync::Mutex::new(None));

    loop {
        let (mut socket, peer) = listener.accept().await?;
        let cache = cache.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match socket.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let line = req.lines().next().unwrap_or("");
            let path = line.split_whitespace().nth(1).unwrap_or("/");

            // Cache 12s + scan bajo demanda
            let (status, body, ctype) = match path {
                "/health" => ("200 OK", r#"{"status":"ok"}"#.to_string(), "application/json"),
                "/json" | "/" | "/index.html" | _ => {
                    // Intentar cache
                    let cached = {
                        let guard = cache.lock().await;
                        if let Some((instant, j, h)) = &*guard {
                            if instant.elapsed().as_secs() < 12 {
                                Some((j.clone(), h.clone()))
                            } else { None }
                        } else { None }
                    };
                    let (json, html) = if let Some((j,h)) = cached {
                        (j, h)
                    } else {
                        println!("  [scan] Generando reporte (350ms, 64 tasks + mDNS/SSDP 900ms) para {}...", peer);
                        let hw = hardware::collect_hardware_info();
                        let subnet = network::local_subnet_cidr();
                        let start = Instant::now();
                        let mut hosts = network::discover_hosts(320, 64).await;
                        hosts = network::enrich_with_arp(hosts).await;
                        hosts = network::enrich_with_mdns_ssdp(hosts, 800).await;
                        let dur = start.elapsed().as_secs_f64();
                        let audit = report::AuditReport::new(hw, hosts, subnet, dur);
                        let j = audit.to_json_pretty().unwrap_or_else(|_| "{}".to_string());
                        let h = audit.to_html();
                        println!("  [scan] Listo en {:.1}s, {} hosts, {} bytes HTML", dur, audit.hosts.len(), h.len());
                        let mut guard = cache.lock().await;
                        *guard = Some((Instant::now(), j.clone(), h.clone()));
                        (j, h)
                    };
                    if path == "/json" {
                        ("200 OK", json, "application/json; charset=utf-8")
                    } else {
                        ("200 OK", html, "text/html; charset=utf-8")
                    }
                }
            };

            let resp = format!(
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{}",
                status,
                ctype,
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.flush().await;
            println!("{} -> {} {} ({} bytes)", peer, path, status, body.len());
        });
    }
}
