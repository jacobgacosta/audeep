use std::path::PathBuf;
use rusqlite::Connection;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("build-cve");
    match cmd {
        "build-cve" | "cve" => build_cve_db()?,
        "help" | "--help" | "-h" => {
            println!("xtask - AuDeep helper");
            println!("  cargo xtask build-cve    # rebuild assets/cve.db from assets/vuln_db.json");
            println!("  cargo xtask help");
        }
        _ => {
            eprintln!("Comando desconocido: {}. Usa 'cargo xtask help'", cmd);
            std::process::exit(1);
        }
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
    if dst.exists() { std::fs::remove_file(&dst)?; }
    let conn = Connection::open(&dst)?;
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
    let mut stmt = conn.prepare("INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?)")?;
    for e in &entries {
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
    conn.execute("INSERT INTO meta VALUES (?1, ?2)", rusqlite::params!["source", "vuln_db.json"])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_service ON vulnerabilities(service)", [])?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)", [])?;
    let count: i64 = conn.query_row("SELECT count(*) FROM vulnerabilities", [], |r| r.get(0))?;
    println!("OK: {} -> {} vulns ({} bytes)", dst.display(), count, std::fs::metadata(&dst)?.len());
    Ok(())
}
