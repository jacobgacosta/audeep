use std::path::PathBuf;
use rusqlite::Connection;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name="xtask", about="AuDeep xtask - helper")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Rebuild assets/cve.db from assets/vuln_db.json (offline, 7 CVEs)
    BuildCve,
    /// Fetch NVD API 2.0 and rebuild cve.db (requiere internet, --limit N)
    FetchNvd {
        /// Cuántos CVEs traer (default 50, max 2000)
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Mantener CVEs locales y mergear (si no, reemplaza)
        #[arg(long)]
        merge: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::BuildCve) {
        Commands::BuildCve => build_cve_db()?,
        Commands::FetchNvd { limit, merge } => fetch_nvd(limit.min(2000), merge).await?,
    }
    Ok(())
}

fn build_cve_db() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let src = root.join("assets").join("vuln_db.json");
    let dst = root.join("assets").join("cve.db");
    println!("Leyendo {}", src.display());
    let data = std::fs::read_to_string(&src)?;
    let entries: Vec<serde_json::Value> = serde_json::from_str(&data)?;
    rebuild_db(&dst, &entries, "vuln_db.json")?;
    Ok(())
}

fn rebuild_db(dst: &PathBuf, entries: &[serde_json::Value], source: &str) -> Result<(), Box<dyn std::error::Error>> {
    if dst.exists() { std::fs::remove_file(dst)?; }
    let conn = Connection::open(dst)?;
    conn.execute_batch(
        "DROP TABLE IF EXISTS vulnerabilities;
         CREATE TABLE vulnerabilities (
           cve TEXT PRIMARY KEY,
           severity TEXT NOT NULL,
           service TEXT NOT NULL,
           affected TEXT NOT NULL,
           description TEXT NOT NULL,
           match_banner_contains TEXT NOT NULL,
           match_ports TEXT NOT NULL,
           recommendation TEXT NOT NULL
         );
         DROP TABLE IF EXISTS meta;
         CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
    )?;
    let mut stmt = conn.prepare("INSERT OR REPLACE INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?)")?;
    for e in entries {
        let cve = e.get("cve").and_then(|v| v.as_str()).unwrap_or("");
        let severity = e.get("severity").and_then(|v| v.as_str()).unwrap_or("");
        let service = e.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let affected = e.get("affected").and_then(|v| v.as_str()).unwrap_or("");
        let description = e.get("description").and_then(|v| v.as_str()).unwrap_or("");
        let recommendation = e.get("recommendation").and_then(|v| v.as_str()).unwrap_or("");
        let banner = e.get("match_banner_contains").cloned().unwrap_or(serde_json::json!([]));
        let ports = e.get("match_ports").cloned().unwrap_or(serde_json::json!([]));
        stmt.execute(rusqlite::params![
            cve, severity, service, affected, description,
            serde_json::to_string(&banner)?,
            serde_json::to_string(&ports)?,
            recommendation
        ])?;
    }
    conn.execute("INSERT INTO meta VALUES (?1, ?2)", rusqlite::params!["count", entries.len().to_string()])?;
    conn.execute("INSERT INTO meta VALUES (?1, ?2)", rusqlite::params!["source", source])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_service ON vulnerabilities(service)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve ON vulnerabilities(cve)", [])?;
    let count: i64 = conn.query_row("SELECT count(*) FROM vulnerabilities", [], |r| r.get(0))?;
    println!("OK: {} -> {} vulns ({} bytes) source={}", dst.display(), count, std::fs::metadata(dst)?.len(), source);
    Ok(())
}

async fn fetch_nvd(limit: usize, merge: bool) -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let dst = root.join("assets").join("cve.db");
    let local_json = root.join("assets").join("vuln_db.json");

    // Traer CVEs recientes (90 días) para que sean relevantes, no del 99
    let end = chrono::Utc::now();
    let start = end - chrono::Duration::days(90);
    let fmt = |d: chrono::DateTime<chrono::Utc>| d.format("%Y-%m-%dT%H:%M:%S.000").to_string();
    println!("Fetching NVD API 2.0 (limit={}, {} -> {})...", limit, fmt(start), fmt(end));
    let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={}&startIndex=0&pubStartDate={}&pubEndDate={}", limit, fmt(start), fmt(end));
    let client = reqwest::Client::builder().user_agent("AuDeep/0.1").timeout(std::time::Duration::from_secs(20)).build()?;
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(format!("NVD HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()).into());
    }
    let j: serde_json::Value = resp.json().await?;
    let vulns = j.get("vulnerabilities").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    println!("NVD retornó {} vulns", vulns.len());

    let mut entries: Vec<serde_json::Value> = Vec::new();
    // Si merge, cargamos locales primero
    if merge {
        let data = std::fs::read_to_string(&local_json)?;
        let local: Vec<serde_json::Value> = serde_json::from_str(&data)?;
        entries.extend(local);
    }
    let mut seen: std::collections::HashSet<String> = entries.iter().filter_map(|e| e.get("cve").and_then(|v| v.as_str()).map(|s| s.to_string())).collect();

    for v in vulns {
        let cve_obj = v.get("cve").cloned().unwrap_or(serde_json::json!({}));
        let cve_id = cve_obj.get("id").and_then(|s| s.as_str()).unwrap_or("").to_string();
        if cve_id.is_empty() || seen.contains(&cve_id) { continue; }
        let desc = cve_obj.get("descriptions").and_then(|a| a.as_array()).and_then(|arr| arr.iter().find(|d| d.get("lang").and_then(|l| l.as_str())==Some("en")).or(arr.first())).and_then(|d| d.get("value")).and_then(|s| s.as_str()).unwrap_or("").to_string();
        // CVSS severity
        let severity = extract_severity(&cve_obj);
        // CPE / service hint
        let (service, affected, ports, banners) = infer_service(&cve_obj, &desc);
        entries.push(serde_json::json!({
            "cve": cve_id,
            "severity": severity,
            "service": service,
            "affected": affected,
            "description": desc.chars().take(400).collect::<String>(),
            "match_banner_contains": banners,
            "match_ports": ports,
            "recommendation": "Ver NVD https://nvd.nist.gov/vuln/detail/".to_string() + &cve_id
        }));
        seen.insert(cve_id);
    }
    println!("Total a guardar: {} (merge={})", entries.len(), merge);
    rebuild_db(&dst, &entries, &format!("NVD+local limit={}", limit))?;
    // actualizar assets/cve.db ya queda embebido en próximo zigbuild
    Ok(())
}

fn extract_severity(cve: &serde_json::Value) -> String {
    // buscar cvssMetricV31 / V30 / V2 en orden
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(arr) = cve.get("metrics").and_then(|m| m.get(key)).and_then(|v| v.as_array()) {
            if let Some(first) = arr.first() {
                if let Some(sev) = first.get("cvssData").and_then(|d| d.get("baseSeverity")).and_then(|s| s.as_str()) {
                    return match sev.to_lowercase().as_str() {
                        "critical" => "critica".to_string(),
                        "high" => "alta".to_string(),
                        "medium" => "media".to_string(),
                        "low" => "baja".to_string(),
                        _ => sev.to_lowercase(),
                    };
                }
                if let Some(score) = first.get("cvssData").and_then(|d| d.get("baseScore")).and_then(|s| s.as_f64()) {
                    return if score >= 9.0 { "critica" } else if score >= 7.0 { "alta" } else if score >= 4.0 { "media" } else { "baja" }.to_string();
                }
            }
        }
    }
    "media".to_string()
}

fn infer_service(cve: &serde_json::Value, desc: &str) -> (String, String, Vec<u16>, Vec<String>) {
    let lower = desc.to_lowercase();
    let cpes: Vec<String> = cve.get("configurations").and_then(|c| c.as_array()).map(|arr| {
        arr.iter().flat_map(|n| n.get("nodes").and_then(|a| a.as_array()).cloned().unwrap_or_default())
           .flat_map(|node| node.get("cpeMatch").and_then(|a| a.as_array()).cloned().unwrap_or_default())
           .filter_map(|m| m.get("criteria").and_then(|s| s.as_str()).map(|s| s.to_string()))
           .collect()
    }).unwrap_or_default();
    let affected = cpes.first().cloned().unwrap_or_else(|| "NVD generic".to_string());
    // heurística servicio por CPE / descripción
    if lower.contains("openssh") || affected.contains("openssh") {
        return ("SSH".to_string(), affected, vec![22], vec!["OpenSSH".to_string()]);
    }
    if lower.contains("smb") || lower.contains("samba") || affected.contains("samba") {
        return ("SMB".to_string(), affected, vec![445,139], vec![]);
    }
    if lower.contains("rdp") || affected.contains("rdp") {
        return ("RDP".to_string(), affected, vec![3389], vec![]);
    }
    if lower.contains("openssl") || lower.contains("heartbleed") || affected.contains("openssl") {
        return ("HTTPS".to_string(), affected, vec![443], vec!["OpenSSL".to_string()]);
    }
    if (lower.contains("apache") || lower.contains("log4j") || lower.contains("nginx")) && affected.to_lowercase().contains("http") {
        // solo si CPE indica http server específico, sino generic sin puertos para evitar falsos positivos
        return ("HTTP".to_string(), affected, vec![80,443,8080], vec![]);
    }
    // GENERIC sin puertos/banners para no disparar falsos positivos; requiere match_banner futuro
    ("GENERIC".to_string(), affected, vec![], vec![])
}
