use crate::{hardware, network, report};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Opciones del servidor.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    /// Segundos que vale un reporte cacheado antes de regenerarlo en segundo plano.
    pub interval_secs: u64,
    /// Si esta seteado, exige `?token=` o la cabecera `X-Auth-Token`.
    pub token: Option<String>,
    pub probe_timeout_ms: u64,
    pub mdns_timeout_ms: u64,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            interval_secs: 60,
            token: None,
            probe_timeout_ms: 320,
            mdns_timeout_ms: 800,
        }
    }
}

#[derive(Default)]
struct Cache {
    generated: Option<Instant>,
    json: String,
    html: String,
    etag: String,
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Pagina crema minimalista para servir markdown sin CDN.
fn docs_page(title: &str, md: &str, links: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AuDeep — {title}</title><style>body{{margin:0;font-family:ui-monospace,monospace;background:#fdfbf7;color:#1c1917;padding:24px;max-width:900px;margin:0 auto}} pre{{white-space:pre-wrap;word-wrap:break-word;background:#fff;border:1px solid #e7e5e4;border-radius:12px;padding:18px;overflow:auto}} a{{color:#0ea5e9}} code{{background:#fffbeb;border:1px solid #e7e5e4;padding:1px 4px;border-radius:4px;font-size:12px}}</style></head><body>{links}<pre>{}</pre></body></html>"#,
        html_escape(md)
    )
}

fn loading_page() -> String {
    r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="2"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AuDeep — Escaneando</title><style>body{margin:0;font-family:system-ui;background:#060a14;color:#e6edf3;display:grid;place-items:center;min-height:100vh} .card{background:#0f172a;border:1px solid #1e293b;border-radius:18px;padding:28px;text-align:center;max-width:480px} .spin{width:44px;height:44px;border:3px solid #1e293b;border-top-color:#38bdf8;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 14px} @keyframes spin{to{transform:rotate(360deg)}} .muted{color:#9aa4b2;font-size:13px} a{color:#38bdf8}</style></head><body><div class="card"><div class="spin"></div><h2>Escaneando red…</h2><p class="muted">Primer scan 8-10s (ARP-first + puertos). Esta pagina se recarga sola.</p><p class="muted">Si ves esto &gt;12s, recarga manual <a href="/">/</a> o mira <a href="/health">/health</a></p><script>setTimeout(()=>location.reload(),2000);</script></div></body></html>"#.to_string()
}

/// Autorizacion opcional por token (query o cabecera).
fn token_ok(opts: &ServeOptions, req: &str, query: &str) -> bool {
    let Some(expected) = opts.token.as_deref() else {
        return true;
    };
    let needle = format!("token={expected}");
    if query.split('&').any(|kv| kv == needle) {
        return true;
    }
    req.lines().any(|l| {
        let l = l.trim();
        l.to_ascii_lowercase().starts_with("x-auth-token:")
            && l.split_once(':')
                .map(|(_, v)| v.trim() == expected)
                .unwrap_or(false)
    })
}

fn response(status: &str, ctype: &str, body: &str, etag: Option<&str>, cors: bool) -> String {
    let mut head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n",
        body.len()
    );
    if cors {
        head.push_str("Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\n");
    }
    if let Some(tag) = etag {
        head.push_str(&format!("ETag: {tag}\r\n"));
    }
    head.push_str("\r\n");
    head.push_str(body);
    head
}

/// Lee el cache: contenido (si hay) y si ya venció.
async fn read_cache(
    cache: &Arc<Mutex<Cache>>,
    ttl: u64,
) -> (Option<(String, String, String)>, bool) {
    let guard = cache.lock().await;
    match guard.generated {
        Some(t) => {
            let item = if guard.json.is_empty() {
                None
            } else {
                Some((guard.json.clone(), guard.html.clone(), guard.etag.clone()))
            };
            (item, t.elapsed().as_secs() >= ttl)
        }
        None => (None, true),
    }
}

/// Lanza un escaneo de fondo si no hay otro en curso.
async fn start_scan_if_idle(
    peer: std::net::SocketAddr,
    opts: ServeOptions,
    cache: Arc<Mutex<Cache>>,
    scanning: Arc<Mutex<bool>>,
) -> bool {
    let arrancar = {
        let mut s = scanning.lock().await;
        if *s {
            false
        } else {
            *s = true;
            true
        }
    };
    if !arrancar {
        return false;
    }
    tokio::spawn(async move {
        println!("  [scan] regenerando reporte para {peer}...");
        let hw = hardware::collect_hardware_info();
        let subnet = network::local_subnet_cidr();
        let start = Instant::now();
        let mut hosts = network::discover_hosts(opts.probe_timeout_ms, 64).await;
        hosts = network::enrich_with_arp(hosts).await;
        hosts = network::enrich_with_mdns_ssdp(hosts, opts.mdns_timeout_ms).await;
        let dur = start.elapsed().as_secs_f64();
        let audit = report::AuditReport::new(hw, hosts, subnet, dur);
        let j = audit.to_json_pretty().unwrap_or_else(|_| "{}".to_string());
        let h = audit.to_html();
        let tag = format!("W/\"{}\"", chrono::Utc::now().timestamp());
        println!("  [scan] listo en {dur:.1}s, {} hosts", audit.hosts.len());
        {
            let mut guard = cache.lock().await;
            *guard = Cache {
                generated: Some(Instant::now()),
                json: j,
                html: h,
                etag: tag,
            };
        }
        {
            let mut s = scanning.lock().await;
            *s = false;
        }
    });
    true
}

pub async fn serve(addr: &str, opts: ServeOptions) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let exposicion = if addr.starts_with("0.0.0.0") || addr.starts_with("[::]") {
        "expuesto en la LAN (modo AP/remoto)"
    } else {
        "solo loopback"
    };
    println!(
        "AuDeep serve en http://{}  ({exposicion}) · Ctrl+C para salir",
        addr
    );
    println!(
        "Endpoints: / HTML · /json JSON · /health · /scan (fuerza reescaneo) · /docs · /docs/guia · /docs/conceptos · cache {}s",
        opts.interval_secs
    );
    if opts.token.is_some() {
        println!("Token activo: agregá ?token=... o la cabecera X-Auth-Token");
    }

    let cache = Arc::new(Mutex::new(Cache::default()));
    let scanning = Arc::new(Mutex::new(false));

    loop {
        let (mut socket, peer) = listener.accept().await?;
        let cache = cache.clone();
        let scanning = scanning.clone();
        let opts = opts.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let Ok(n) = socket.read(&mut buf).await else {
                return;
            };
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let first = req.lines().next().unwrap_or("");
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("GET").to_ascii_uppercase();
            let target = parts.next().unwrap_or("/").to_string();
            let (path, query) = match target.split_once('?') {
                Some((p, q)) => (p.to_string(), q.to_string()),
                None => (target.clone(), String::new()),
            };

            if method == "OPTIONS" {
                let resp = response("204 No Content", "text/plain", "", None, true);
                let _ = socket.write_all(resp.as_bytes()).await;
                return;
            }

            if !token_ok(&opts, &req, &query) {
                let body = r#"{"error":"token requerido"}"#;
                let resp = response("401 Unauthorized", "application/json", body, None, true);
                let _ = socket.write_all(resp.as_bytes()).await;
                println!("{peer} -> {path} 401 (token)");
                return;
            }

            let if_none_match = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("if-none-match:"))
                .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()));

            let (status, body, ctype, etag) = match path.as_str() {
                "/health" => (
                    "200 OK",
                    r#"{"status":"ok"}"#.to_string(),
                    "application/json",
                    None,
                ),
                "/docs" | "/docs/" | "/docs.md" => {
                    let md = include_str!("../docs/architecture.md");
                    let links = r#"<a href="/" style="font-family:ui-monospace;font-size:12px">← Volver al dashboard</a> · <a href="/docs/guia" style="font-family:ui-monospace;font-size:12px">Guía simple (sin tecnicismos)</a> · <a href="/docs/conceptos" style="font-family:ui-monospace;font-size:12px">Conceptos (qué / para qué)</a>"#;
                    (
                        "200 OK",
                        docs_page("Docs", md, links),
                        "text/html; charset=utf-8",
                        None,
                    )
                }
                "/docs/guia" | "/docs/guia.md" => {
                    let md = include_str!("../docs/guia-conceptos.md");
                    let links = r#"<a href="/" style="font-family:ui-monospace;font-size:12px">← Volver al dashboard</a> · <a href="/docs" style="font-family:ui-monospace;font-size:12px">Arquitectura</a> · <a href="/docs/conceptos" style="font-family:ui-monospace;font-size:12px">Conceptos</a>"#;
                    (
                        "200 OK",
                        docs_page("Guía simple", md, links),
                        "text/html; charset=utf-8",
                        None,
                    )
                }
                "/docs/conceptos" | "/docs/conceptos.md" => {
                    let md = include_str!("../docs/conceptos.md");
                    let links = r#"<a href="/" style="font-family:ui-monospace;font-size:12px">← Volver al dashboard</a> · <a href="/docs" style="font-family:ui-monospace;font-size:12px">Arquitectura</a>"#;
                    (
                        "200 OK",
                        docs_page("Conceptos", md, links),
                        "text/html; charset=utf-8",
                        None,
                    )
                }
                _ => {
                    let forzar = path == "/scan" || query.split('&').any(|kv| kv == "force=1");
                    let (cached, vencido) = read_cache(&cache, opts.interval_secs).await;

                    if forzar {
                        start_scan_if_idle(peer, opts.clone(), cache.clone(), scanning.clone())
                            .await;
                        (
                            "202 Accepted",
                            r#"{"status":"scanning","retry":2}"#.to_string(),
                            "application/json",
                            None,
                        )
                    } else if cached.is_none() || vencido {
                        // Se regenera de fondo; mientras tanto se sirve lo viejo.
                        start_scan_if_idle(peer, opts.clone(), cache.clone(), scanning.clone())
                            .await;
                        match cached {
                            Some((json, html, tag)) => {
                                if path == "/json" {
                                    ("200 OK", json, "application/json; charset=utf-8", Some(tag))
                                } else {
                                    ("200 OK", html, "text/html; charset=utf-8", Some(tag))
                                }
                            }
                            None if path == "/json" => (
                                "202 Accepted",
                                r#"{"status":"scanning","retry":2}"#.to_string(),
                                "application/json",
                                None,
                            ),
                            None => ("200 OK", loading_page(), "text/html; charset=utf-8", None),
                        }
                    } else {
                        match cached {
                            Some((_, _, tag)) if if_none_match.as_deref() == Some(tag.as_str()) => {
                                ("304 Not Modified", String::new(), "text/plain", Some(tag))
                            }
                            Some((json, html, tag)) => {
                                if path == "/json" {
                                    ("200 OK", json, "application/json; charset=utf-8", Some(tag))
                                } else {
                                    ("200 OK", html, "text/html; charset=utf-8", Some(tag))
                                }
                            }
                            None => ("200 OK", loading_page(), "text/html; charset=utf-8", None),
                        }
                    }
                }
            };

            let resp = response(status, ctype, &body, etag.as_deref(), true);
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.flush().await;
            println!("{peer} -> {path} {status} ({} bytes)", body.len());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_optional_and_checked_in_query_or_header() {
        let abierto = ServeOptions::default();
        assert!(token_ok(&abierto, "GET / HTTP/1.1", ""));

        let cerrado = ServeOptions {
            token: Some("s3creto".to_string()),
            ..Default::default()
        };
        assert!(!token_ok(&cerrado, "GET / HTTP/1.1", ""));
        assert!(token_ok(
            &cerrado,
            "GET /?token=s3creto HTTP/1.1",
            "token=s3creto"
        ));
        assert!(token_ok(
            &cerrado,
            "GET /json HTTP/1.1\r\nX-Auth-Token: s3creto\r\n",
            ""
        ));
        assert!(!token_ok(
            &cerrado,
            "GET /json HTTP/1.1\r\nX-Auth-Token: otro\r\n",
            ""
        ));
    }

    #[test]
    fn responses_carry_security_headers_and_etag() {
        let r = response("200 OK", "application/json", "{}", Some("W/\"7\""), true);
        assert!(r.contains("X-Content-Type-Options: nosniff"));
        assert!(r.contains("Referrer-Policy: no-referrer"));
        assert!(r.contains("ETag: W/\"7\""));
        assert!(r.contains("Access-Control-Allow-Origin: *"));
        assert!(r.ends_with("{}"));

        let sin_cors = response("401 Unauthorized", "application/json", "x", None, false);
        assert!(!sin_cors.contains("Access-Control-Allow-Origin"));
    }

    #[test]
    fn docs_and_loading_pages_render() {
        let p = docs_page("Docs", "# Titulo <script>", "<a href=\"/\">volver</a>");
        assert!(p.contains("&lt;script&gt;"), "el markdown se escapa");
        assert!(p.contains("volver"));
        assert!(loading_page().contains("Escaneando"));
    }
}
