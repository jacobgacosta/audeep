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
// cve.db embebido como fallback binario (generado via scripts/build_cve_db.py)
static DB_SQLITE_BYTES: &[u8] = include_bytes!("../assets/cve.db");

fn load_db_from_sqlite_bytes(bytes: &[u8]) -> Option<Vec<VulnEntry>> {
    use rusqlite::Connection;
    use std::io::Write;
    // Escribir a temp y abrir - rusqlite bundled no soporta deserialize directo sin feature
    // Para mantener offline/portable, usamos in-memory y populate via SQL si bytes no son SQLite válido
    // Intentamos abrir como archivo temporal
    let mut tmp = std::env::temp_dir().join(format!("audeep_cve_{}.db", std::process::id()));
    // Si ya existe y es del mismo tamaño, reutilizar
    let try_open = || -> Option<Vec<VulnEntry>> {
        if bytes.len() < 100 || &bytes[0..6] != b"SQLite" {
            return None;
        }
        // Escribir temp
        let mut f = std::fs::File::create(&tmp).ok()?;
        f.write_all(bytes).ok()?;
        let conn = Connection::open(&tmp).ok()?;
        let mut stmt = conn.prepare("SELECT cve, severity, service, affected, description, match_banner_contains, match_ports, recommendation FROM vulnerabilities").ok()?;
        let rows = stmt.query_map([], |row| {
            let banner_json: String = row.get(5)?;
            let ports_json: String = row.get(6)?;
            let banners: Vec<String> = serde_json::from_str(&banner_json).unwrap_or_default();
            let ports: Vec<u16> = serde_json::from_str(&ports_json).unwrap_or_default();
            Ok(VulnEntry {
                cve: row.get(0)?,
                severity: row.get(1)?,
                service: row.get(2)?,
                affected: row.get(3)?,
                description: row.get(4)?,
                match_banner_contains: banners,
                match_ports: ports,
                recommendation: row.get(7)?,
            })
        }).ok()?;
        let mut out = Vec::new();
        for r in rows.flatten() { out.push(r); }
        if out.is_empty() { None } else { Some(out) }
    };
    let res = try_open();
    let _ = std::fs::remove_file(&tmp);
    res
}

fn load_db_from_sqlite_file(path: &std::path::Path) -> Option<Vec<VulnEntry>> {
    use rusqlite::Connection;
    if !path.exists() { return None; }
    let conn = Connection::open(path).ok()?;
    let mut stmt = conn.prepare("SELECT cve, severity, service, affected, description, match_banner_contains, match_ports, recommendation FROM vulnerabilities").ok()?;
    let rows = stmt.query_map([], |row| {
        let banner_json: String = row.get(5)?;
        let ports_json: String = row.get(6)?;
        let banners: Vec<String> = serde_json::from_str(&banner_json).unwrap_or_default();
        let ports: Vec<u16> = serde_json::from_str(&ports_json).unwrap_or_default();
        Ok(VulnEntry {
            cve: row.get(0)?,
            severity: row.get(1)?,
            service: row.get(2)?,
            affected: row.get(3)?,
            description: row.get(4)?,
            match_banner_contains: banners,
            match_ports: ports,
            recommendation: row.get(7)?,
        })
    }).ok()?;
    let mut out = Vec::new();
    for r in rows.flatten() { out.push(r); }
    if out.is_empty() { None } else { Some(out) }
}

pub fn load_db() -> Vec<VulnEntry> {
    // 1) Intenta archivo junto al binario (para USB actualizable sin recompilar)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for cand in [dir.join("cve.db"), dir.join("assets/cve.db")] {
                if let Some(v) = load_db_from_sqlite_file(&cand) { return v; }
            }
        }
    }
    // 2) Intenta assets/cve.db en cwd (dev)
    for cand in [std::path::Path::new("assets/cve.db"), std::path::Path::new("cve.db")] {
        if let Some(v) = load_db_from_sqlite_file(cand) { return v; }
    }
    // 3) Intenta bytes embebidos
    if let Some(v) = load_db_from_sqlite_bytes(DB_SQLITE_BYTES) { return v; }
    // 4) Fallback JSON embebido
    serde_json::from_str(DB_JSON).unwrap_or_default()
}

pub fn query_sqlite(sql: &str) -> Result<Vec<VulnEntry>, String> {
    use rusqlite::Connection;
    // Abre DB embebida en memoria para queries ad-hoc
    let db = load_db();
    // Si el SQL es simple SELECT, filtramos en memoria; para compatibilidad real, usamos temp file
    // Implementación mínima: soporta "SELECT * FROM vulnerabilities WHERE service='SSH'" etc via rusqlite
    if let Some(v) = load_db_from_sqlite_bytes(DB_SQLITE_BYTES) {
        // Re-abrir temp para ejecutar SQL directo
        let mut tmp = std::env::temp_dir().join(format!("audeep_q_{}.db", std::process::id()));
        if DB_SQLITE_BYTES.len() >= 100 && &DB_SQLITE_BYTES[0..6] == b"SQLite" {
            let _ = std::fs::write(&tmp, DB_SQLITE_BYTES);
            if let Ok(conn) = Connection::open(&tmp) {
                if let Ok(mut stmt) = conn.prepare(sql) {
                    let cols = stmt.column_count();
                    // Solo soportamos queries que retornan esquema vulnerabilities
                    if cols >= 8 {
                        let rows = stmt.query_map([], |row| {
                            let bj: String = row.get(5).unwrap_or_default();
                            let pj: String = row.get(6).unwrap_or_default();
                            Ok(VulnEntry {
                                cve: row.get(0).unwrap_or_default(),
                                severity: row.get(1).unwrap_or_default(),
                                service: row.get(2).unwrap_or_default(),
                                affected: row.get(3).unwrap_or_default(),
                                description: row.get(4).unwrap_or_default(),
                                match_banner_contains: serde_json::from_str(&bj).unwrap_or_default(),
                                match_ports: serde_json::from_str(&pj).unwrap_or_default(),
                                recommendation: row.get(7).unwrap_or_default(),
                            })
                        });
                        if let Ok(rows) = rows {
                            let out: Vec<_> = rows.flatten().collect();
                            let _ = std::fs::remove_file(&tmp);
                            return Ok(out);
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(&tmp);
        }
        // Fallback filtro en memoria si SQL no es directo
        let _ = tmp;
    }
    // Fallback en memoria: parse simple WHERE service='X'
    if sql.to_uppercase().contains("WHERE") {
        let svc = sql.split('\'').nth(1).unwrap_or("").to_uppercase();
        let filtered: Vec<_> = db.into_iter().filter(|e| e.service.to_uppercase().contains(&svc) || e.cve.contains(&svc)).collect();
        return Ok(filtered);
    }
    Ok(db)
}

pub fn check_port(port: &PortResult, db: &[VulnEntry]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let banner_upper = port.banner.as_ref().map(|b| b.to_uppercase()).unwrap_or_default();
    let svc_hint = port.service_hint.clone().unwrap_or_default();

    for entry in db {
        // Coincidencia por puerto (para vulns sin banner, como SMB/RDP)
        let port_match = !entry.match_ports.is_empty() && entry.match_ports.contains(&port.port);
        // Coincidencia por banner
        let banner_match = !entry.match_banner_contains.is_empty()
            && entry
                .match_banner_contains
                .iter()
                .any(|needle| banner_upper.contains(&needle.to_uppercase()));

        // Si la entrada tiene match_ports, aplica solo si puerto coincide
        // Si tiene banner_contains, requiere banner match
        // Para entradas con ambos vacíos no aplica
        let should_flag = if !entry.match_ports.is_empty() && !entry.match_banner_contains.is_empty() {
            port_match && banner_match
        } else if !entry.match_ports.is_empty() {
            // Para SMB/RDP: si puerto abierto y servicio hint coincide o puerto coincide directo
            port_match && (entry.service == svc_hint || entry.service == "SMB" && port.port == 445 || entry.service == "RDP" && port.port == 3389)
        } else if !entry.match_banner_contains.is_empty() {
            banner_match
        } else {
            false
        };

        // Caso especial SMB/RDP: marcar si puerto abierto y no hay banner, pero sí vulnerabilidad conocida
        // Ya cubierto arriba, pero afinamos severidad
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
        all.extend(check_port(p, &db));
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
    #[test]
    fn test_ssh_old_banner() {
        let port = PortResult {
            port: 22,
            state: "open".to_string(),
            banner: Some("SSH-2.0-OpenSSH_7.2p2".to_string()),
            service_hint: Some("SSH".to_string()),
        };
        let findings = check_port(&port, &load_db());
        assert!(findings.iter().any(|f| f.cve == "CVE-2018-15473"));
    }
    #[test]
    fn test_smb_port() {
        let port = PortResult {
            port: 445,
            state: "open".to_string(),
            banner: None,
            service_hint: Some("SMB".to_string()),
        };
        let findings = check_port(&port, &load_db());
        assert!(findings.iter().any(|f| f.cve == "CVE-2017-0144"));
    }
}
