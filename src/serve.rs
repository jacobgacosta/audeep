use crate::{hardware, network, report};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn serve(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("AuDeep serve en http://{}  (Ctrl+C para salir)", addr);
    println!("Endpoints: /  -> HTML (mamón), /json -> JSON, /health -> ok (scan cache 12s)");

    // Cache simple: (Instant, json, html) + flag scanning
    let cache: std::sync::Arc<tokio::sync::Mutex<Option<(Instant, String, String)>>> = std::sync::Arc::new(tokio::sync::Mutex::new(None));
    let scanning: std::sync::Arc<tokio::sync::Mutex<bool>> = std::sync::Arc::new(tokio::sync::Mutex::new(false));

    loop {
        let (mut socket, peer) = listener.accept().await?;
        let cache = cache.clone();
        let scanning = scanning.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match socket.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let line = req.lines().next().unwrap_or("");
            let path = line.split_whitespace().nth(1).unwrap_or("/");

            // Health instant, / y /json con loading no-bloqueante
            let (status, body, ctype) = match path {
                "/health" => ("200 OK", r#"{"status":"ok"}"#.to_string(), "application/json"),
                _ => {
                    let cached = {
                        let guard = cache.lock().await;
                        if let Some((instant, j, h)) = &*guard {
                            if instant.elapsed().as_secs() < 12 { Some((j.clone(), h.clone())) } else { None }
                        } else { None }
                    };
                    if let Some((j,h)) = cached {
                        if path == "/json" { ("200 OK", j, "application/json; charset=utf-8") } else { ("200 OK", h, "text/html; charset=utf-8") }
                    } else {
                        let should_spawn = {
                            let mut s = scanning.lock().await;
                            if *s { false } else { *s = true; true }
                        };
                        if should_spawn {
                            let cache_bg = cache.clone();
                            let scanning_bg = scanning.clone();
                            tokio::spawn(async move {
                                println!("  [scan] Generando reporte background para {}...", peer);
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
                                println!("  [scan] Listo background en {:.1}s, {} hosts", dur, audit.hosts.len());
                                {
                                    let mut guard = cache_bg.lock().await;
                                    *guard = Some((Instant::now(), j, h));
                                }
                                {
                                    let mut s = scanning_bg.lock().await;
                                    *s = false;
                                }
                            });
                        }
                        if path == "/json" {
                            ("202 Accepted", r#"{"status":"scanning","retry":2}"#.to_string(), "application/json")
                        } else {
                            let loading = r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="2"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AuDeep — Escaneando</title><style>body{margin:0;font-family:system-ui;background:#060a14;color:#e6edf3;display:grid;place-items:center;min-height:100vh} .card{background:#0f172a;border:1px solid #1e293b;border-radius:18px;padding:28px;text-align:center;max-width:480px} .spin{width:44px;height:44px;border:3px solid #1e293b;border-top-color:#38bdf8;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 14px} @keyframes spin{to{transform:rotate(360deg)}} .muted{color:#9aa4b2;font-size:13px} a{color:#38bdf8}</style></head><body><div class="card"><div class="spin"></div><h2>Escaneando red…</h2><p class="muted">Primer scan 8-10s (254 hosts + mDNS/SSDP). Esta página se recarga sola.</p><p class="muted">Si ves esto >12s, recarga manual <a href="/">/</a> o abre <a href="/health">/health</a></p><script>setTimeout(()=>location.reload(),2000);</script></div></body></html>"#;
                            ("200 OK", loading.to_string(), "text/html; charset=utf-8")
                        }
                    }
                }
            };

            let resp = format!(
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\n\r\n{}",
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
