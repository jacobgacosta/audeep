use crate::scanner::PortResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnEntry {
    pub cve: String,
    pub severity: String, // critica | alta | media | baja
    pub service: String,
    pub affected: String,
    pub description: String,
    #[serde(default)]
    pub match_banner_contains: Vec<String>,
    #[serde(default)]
    pub match_ports: Vec<u16>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub cve: String,
    pub severity: String,
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
    pub description: String,
    pub recommendation: String,
}

static DB_JSON: &str = include_str!("../assets/vuln_db.json");
// cve.db embebido como fallback binario (generado via scripts/build_cve_db.py o xtask)
static DB_SQLITE_BYTES: &[u8] = include_bytes!("../assets/cve.db");

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<VulnEntry> {
    let banner_json: String = row.get(5)?;
    let ports_json: String = row.get(6)?;
    Ok(VulnEntry {
        cve: row.get(0)?,
        severity: row.get(1)?,
        service: row.get(2)?,
        affected: row.get(3)?,
        description: row.get(4)?,
        match_banner_contains: serde_json::from_str(&banner_json).unwrap_or_default(),
        match_ports: serde_json::from_str(&ports_json).unwrap_or_default(),
        recommendation: row.get(7)?,
    })
}

const SELECT_SQL: &str = "SELECT cve, severity, service, affected, description, match_banner_contains, match_ports, recommendation FROM vulnerabilities";

fn load_db_from_sqlite_bytes(bytes: &[u8]) -> Option<Vec<VulnEntry>> {
    use rusqlite::Connection;
    use std::io::Write;
    // rusqlite bundled no expone deserialize directo: se materializa el archivo
    // embebido en temp **una sola vez** (load_db está cacheado con OnceLock).
    if bytes.len() < 100 || &bytes[0..6] != b"SQLite" {
        return None;
    }
    let tmp = std::env::temp_dir().join(format!("audeep_cve_{}.db", std::process::id()));
    let res = (|| -> Option<Vec<VulnEntry>> {
        let mut f = std::fs::File::create(&tmp).ok()?;
        f.write_all(bytes).ok()?;
        let conn = Connection::open(&tmp).ok()?;
        let mut stmt = conn.prepare(SELECT_SQL).ok()?;
        let rows = stmt.query_map([], row_to_entry).ok()?;
        let out: Vec<VulnEntry> = rows.flatten().collect();
        if out.is_empty() { None } else { Some(out) }
    })();
    let _ = std::fs::remove_file(&tmp);
    res
}

fn load_db_from_sqlite_file(path: &std::path::Path) -> Option<Vec<VulnEntry>> {
    use rusqlite::Connection;
    if !path.exists() {
        return None;
    }
    let conn = Connection::open(path).ok()?;
    let mut stmt = conn.prepare(SELECT_SQL).ok()?;
    let rows = stmt.query_map([], row_to_entry).ok()?;
    let out: Vec<VulnEntry> = rows.flatten().collect();
    if out.is_empty() { None } else { Some(out) }
}

fn load_db_uncached() -> Vec<VulnEntry> {
    // 1) Intenta archivo junto al binario (para USB actualizable sin recompilar)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for cand in [dir.join("cve.db"), dir.join("assets/cve.db")] {
                if let Some(v) = load_db_from_sqlite_file(&cand) {
                    return v;
                }
            }
        }
    }
    // 2) Intenta assets/cve.db en cwd (dev)
    for cand in [
        std::path::Path::new("assets/cve.db"),
        std::path::Path::new("cve.db"),
    ] {
        if let Some(v) = load_db_from_sqlite_file(cand) {
            return v;
        }
    }
    // 3) Intenta bytes embebidos
    if let Some(v) = load_db_from_sqlite_bytes(DB_SQLITE_BYTES) {
        return v;
    }
    // 4) Fallback JSON embebido
    serde_json::from_str(DB_JSON).unwrap_or_default()
}

/// Base de vulnerabilidades, cargada una sola vez por proceso.
///
/// Antes se reconstruía en **cada host** (`check_host` la llamaba por host) y en
/// cada llamada materializaba la SQLite embebida en un archivo temporal: con 69
/// hosts eran 69 escrituras a disco. Ahora se devuelve una referencia estática.
pub fn load_db() -> &'static [VulnEntry] {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Vec<VulnEntry>> = OnceLock::new();
    CACHE.get_or_init(load_db_uncached).as_slice()
}

pub fn check_port(port: &PortResult, db: &[VulnEntry]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let banner_upper = port
        .banner
        .as_ref()
        .map(|b| b.to_uppercase())
        .unwrap_or_default();
    let svc_hint = port.service_hint.clone().unwrap_or_default();

    for entry in db {
        let port_match = !entry.match_ports.is_empty() && entry.match_ports.contains(&port.port);
        let banner_match = !entry.match_banner_contains.is_empty()
            && entry
                .match_banner_contains
                .iter()
                .any(|needle| banner_upper.contains(&needle.to_uppercase()));

        // Con ambos criterios exige los dos; con uno solo, ese.
        let should_flag = match (
            entry.match_ports.is_empty(),
            entry.match_banner_contains.is_empty(),
        ) {
            (false, false) => port_match && banner_match,
            (false, true) => port_match,
            (true, false) => banner_match,
            (true, true) => false,
        };

        if should_flag {
            findings.push(Finding {
                cve: entry.cve.clone(),
                severity: entry.severity.clone(),
                port: port.port,
                service: entry.service.clone(),
                banner: port.banner.clone(),
                description: entry.description.clone(),
                recommendation: entry.recommendation.clone(),
            });
        }
    }

    findings
}

pub fn check_host(open_ports: &[PortResult]) -> Vec<Finding> {
    let db = load_db();
    let mut all = Vec::new();
    for p in open_ports.iter().filter(|p| p.state == "open") {
        all.extend(check_port(p, db));
    }
    // dedup por CVE+port
    let mut seen = std::collections::HashSet::new();
    all.retain(|f| seen.insert((f.cve.clone(), f.port)));
    all.sort_by(|a, b| {
        let ord = severity_rank(&b.severity).cmp(&severity_rank(&a.severity));
        if ord == std::cmp::Ordering::Equal {
            a.cve.cmp(&b.cve)
        } else {
            ord
        }
    });
    all
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critica" => 4,
        "alta" => 3,
        "media" => 2,
        "baja" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(port: u16, banner: Option<&str>, hint: &str) -> PortResult {
        PortResult {
            port,
            state: "open".to_string(),
            banner: banner.map(|b| b.to_string()),
            service_hint: Some(hint.to_string()),
        }
    }

    #[test]
    fn db_is_loaded_once() {
        let a = load_db();
        let b = load_db();
        assert!(
            !a.is_empty(),
            "la base de vulnerabilidades no puede estar vacia"
        );
        assert!(
            std::ptr::eq(a.as_ptr(), b.as_ptr()),
            "load_db debe estar cacheada"
        );
    }

    #[test]
    fn test_ssh_old_banner() {
        let p = port(22, Some("SSH-2.0-OpenSSH_7.2p2"), "SSH");
        let findings = check_port(&p, load_db());
        assert!(findings.iter().any(|f| f.cve == "CVE-2018-15473"));
    }

    #[test]
    fn test_smb_port() {
        let p = port(445, None, "SMB");
        let findings = check_port(&p, load_db());
        assert!(findings.iter().any(|f| f.cve == "CVE-2017-0144"));
    }

    #[test]
    fn rdp_port_flagged_and_http_without_banner_not_flagged() {
        let rdp = port(3389, None, "RDP");
        assert!(
            check_port(&rdp, load_db())
                .iter()
                .any(|f| f.cve == "CVE-2019-0708")
        );
        // Apache/Log4Shell requiere banner: el puerto solo no alcanza
        let http = port(80, Some("nginx/1.18.0"), "HTTP");
        assert!(
            !check_port(&http, load_db())
                .iter()
                .any(|f| f.cve == "CVE-2021-44228")
        );
    }

    #[test]
    fn findings_are_sorted_by_severity() {
        let ports = [
            port(445, None, "SMB"),
            port(22, Some("SSH-2.0-OpenSSH_7.2p2"), "SSH"),
        ];
        let findings = check_host(&ports);
        assert!(findings.len() >= 2);
        assert_eq!(findings[0].severity, "critica");
    }
}
