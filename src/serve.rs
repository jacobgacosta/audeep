use crate::{hardware, network, report};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn serve(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("AuDeep serve en http://{}  (Ctrl+C para salir)", addr);
    println!("Endpoints: /  -> HTML, /json -> JSON, /health -> ok");

    loop {
        let (mut socket, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match socket.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let line = req.lines().next().unwrap_or("");
            let path = line.split_whitespace().nth(1).unwrap_or("/");

            // Generar reporte bajo demanda (cache 5s si se quiere optimizar)
            let (status, body, ctype) = match path {
                "/json" => {
                    let hw = hardware::collect_hardware_info();
                    let subnet = network::local_subnet_cidr();
                    let start = Instant::now();
                    let mut hosts = network::discover_hosts(350, 64).await;
                    hosts = network::enrich_with_arp(hosts).await;
                    let dur = start.elapsed().as_secs_f64();
                    let audit = report::AuditReport::new(hw, hosts, subnet, dur);
                    let json = audit.to_json_pretty().unwrap_or_else(|_| "{}".to_string());
                    ("200 OK", json, "application/json; charset=utf-8")
                }
                "/health" => ("200 OK", r#"{"status":"ok"}"#.to_string(), "application/json"),
                _ => {
                    // Para "/" y cualquier otra ruta, servir HTML (incluye portal cautivo)
                    let hw = hardware::collect_hardware_info();
                    let subnet = network::local_subnet_cidr();
                    let start = Instant::now();
                    let mut hosts = network::discover_hosts(350, 64).await;
                    hosts = network::enrich_with_arp(hosts).await;
                    let dur = start.elapsed().as_secs_f64();
                    let audit = report::AuditReport::new(hw, hosts, subnet, dur);
                    let html = audit.to_html();
                    ("200 OK", html, "text/html; charset=utf-8")
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
