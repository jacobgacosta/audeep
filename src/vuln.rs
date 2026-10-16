use crate::probe;
use crate::scanner::PortResult;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Rango de versiones afectadas por un aviso, por producto.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    pub product: String,
    pub min: String,
    pub max: String,
}

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
    #[serde(default)]
    pub match_versions: Vec<VersionRange>,
    /// Certeza declarada del aviso. Si falta se deduce del tipo de regla.
    #[serde(default)]
    pub confidence: Option<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub cve: String,
    pub severity: String,
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
    /// `confirmado` | `probable` | `sospecha`: distingue lo que se probo de lo
    /// que solo se deduce del puerto abierto.
    pub confidence: String,
    /// Con que se sostiene el hallazgo (banner, version, negociacion activa).
    pub evidence: Option<String>,
    pub description: String,
    pub recommendation: String,
}

static DB_JSON: &str = include_str!("../assets/vuln_db.json");
// cve.db embebido como complemento (NVD): el JSON curado manda.
static DB_SQLITE_BYTES: &[u8] = include_bytes!("../assets/cve.db");

const SELECT_SQL: &str = "SELECT cve, severity, service, affected, description, match_banner_contains, match_ports, recommendation FROM vulnerabilities";

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
        // La base SQLite no guarda rangos de version: los aporta el JSON curado.
        match_versions: Vec::new(),
        confidence: None,
        recommendation: row.get(7)?,
    })
}

fn entries_from_sqlite_bytes(bytes: &[u8]) -> Option<Vec<VulnEntry>> {
    use rusqlite::Connection;
    use std::io::Write;
    if bytes.len() < 100 || &bytes[0..6] != b"SQLite" {
        return None;
    }
    // Se materializa el archivo embebido en temp **una sola vez** (load_db cachea).
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

fn entries_from_sqlite_file(path: &Path) -> Option<Vec<VulnEntry>> {
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

/// CVEs extra que aporta la base SQLite (junto al binario, en cwd o embebida).
fn extra_from_sqlite() -> Vec<VulnEntry> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for cand in [dir.join("cve.db"), dir.join("assets/cve.db")] {
                if let Some(v) = entries_from_sqlite_file(&cand) {
                    return v;
                }
            }
        }
    }
    for cand in [Path::new("assets/cve.db"), Path::new("cve.db")] {
        if let Some(v) = entries_from_sqlite_file(cand) {
            return v;
        }
    }
    entries_from_sqlite_bytes(DB_SQLITE_BYTES).unwrap_or_default()
}

/// Base curada + lo que aporte la SQLite, sin duplicar CVEs.
///
/// El JSON es la fuente de verdad de las reglas escritas a mano (incluidos los
/// rangos de versión, que la tabla SQLite no guarda); la SQLite solo agrega
/// CVEs que el curado no cubre (por ejemplo los que baja `xtask fetch-nvd`).
fn load_db_uncached() -> Vec<VulnEntry> {
    let mut entries: Vec<VulnEntry> = serde_json::from_str(DB_JSON).unwrap_or_default();
    let mut known: HashSet<String> = entries.iter().map(|e| e.cve.clone()).collect();
    for e in extra_from_sqlite() {
        if known.insert(e.cve.clone()) {
            entries.push(e);
        }
    }
    entries
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

fn banner_matches(entry: &VulnEntry, banner_upper: &str) -> bool {
    !entry.match_banner_contains.is_empty()
        && entry
            .match_banner_contains
            .iter()
            .any(|needle| banner_upper.contains(&needle.to_uppercase()))
}

/// Acierto por versión: se parsea el banner del servicio y se compara contra
/// los rangos publicados por producto.
fn version_matches(entry: &VulnEntry, banner: Option<&str>) -> bool {
    if entry.match_versions.is_empty() {
        return false;
    }
    let Some((product, version)) = banner.and_then(probe::parse_ssh_banner) else {
        return false;
    };
    entry.match_versions.iter().any(|r| {
        r.product.eq_ignore_ascii_case(&product)
            && probe::version_in_range(&version, &r.min, &r.max)
    })
}

/// Certeza del hallazgo.
///
/// Si el aviso la declara se respeta; si no, se deduce: una coincidencia de
/// banner o de version es "probable" (el banner lo declara el propio equipo) y
/// un puerto abierto sin mas es "sospecha".
fn confidence_for(entry: &VulnEntry, banner_match: bool, version_match: bool) -> &'static str {
    if let Some(declared) = entry.confidence.as_deref() {
        return match declared {
            "confirmado" => "confirmado",
            "probable" => "probable",
            _ => "sospecha",
        };
    }
    if banner_match || version_match {
        "probable"
    } else {
        "sospecha"
    }
}

/// Evidencia legible de por que se marco el hallazgo.
fn evidence_for(port: &PortResult, banner_match: bool, version_match: bool) -> Option<String> {
    let banner = port.banner.as_deref()?;
    let first = banner.lines().next().unwrap_or(banner);
    let short: String = first.chars().take(90).collect();
    if banner.starts_with("SMB") {
        return Some(format!("negociacion SMB real: {short}"));
    }
    if version_match {
        return Some(format!("banner declara version afectada: {short}"));
    }
    if banner_match {
        return Some(format!("banner coincide: {short}"));
    }
    None
}

pub fn check_port(port: &PortResult, db: &[VulnEntry]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let banner_upper = port
        .banner
        .as_ref()
        .map(|b| b.to_uppercase())
        .unwrap_or_default();

    for entry in db {
        let port_rule = !entry.match_ports.is_empty();
        let banner_rule = !entry.match_banner_contains.is_empty();
        let version_rule = !entry.match_versions.is_empty();

        let port_match = port_rule && entry.match_ports.contains(&port.port);
        let banner_match = banner_matches(entry, &banner_upper);
        let version_match = version_matches(entry, port.banner.as_deref());

        // Sin criterios no aplica. Si hay puerto + (banner|version), el puerto es
        // obligatorio y después alcanza una de las dos señales de contenido.
        let should_flag = if !port_rule && !banner_rule && !version_rule {
            false
        } else if port_rule && (banner_rule || version_rule) {
            port_match && (banner_match || version_match)
        } else {
            (!port_rule || port_match)
                && (!banner_rule || banner_match)
                && (!version_rule || version_match)
        };

        if should_flag {
            findings.push(Finding {
                cve: entry.cve.clone(),
                severity: entry.severity.clone(),
                port: port.port,
                service: entry.service.clone(),
                banner: port.banner.clone(),
                confidence: confidence_for(entry, banner_match, version_match).to_string(),
                evidence: evidence_for(port, banner_match, version_match),
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
    let mut seen = HashSet::new();
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
    fn confidence_separates_confirmed_from_suspected() {
        let smb1 = port(445, Some("SMB1 habilitado"), "SMB");
        let f = check_port(&smb1, load_db())
            .into_iter()
            .find(|f| f.cve == "CVE-2017-0144")
            .expect("SMB1 debe marcar EternalBlue");
        assert_eq!(
            f.confidence, "confirmado",
            "la negociacion SMB1 es prueba activa"
        );
        assert!(f.evidence.as_deref().unwrap().contains("negociacion SMB"));

        let rdp = port(3389, None, "RDP");
        let f = check_port(&rdp, load_db())
            .into_iter()
            .find(|f| f.cve == "CVE-2019-0708")
            .expect("RDP debe marcarse");
        assert_eq!(f.confidence, "sospecha", "puerto solo no confirma version");
        assert!(f.evidence.is_none(), "sin banner no hay evidencia");

        let ssh = port(22, Some("SSH-2.0-OpenSSH_7.2p2"), "SSH");
        let f = check_port(&ssh, load_db())
            .into_iter()
            .find(|f| f.cve == "CVE-2018-15473")
            .expect("OpenSSH 7.2 debe marcarse");
        assert_eq!(f.confidence, "probable");
        assert!(f.evidence.as_deref().unwrap().contains("version afectada"));
    }

    fn port(port: u16, banner: Option<&str>, hint: &str) -> PortResult {
        PortResult {
            port,
            state: "open".to_string(),
            banner: banner.map(|b| b.to_string()),
            service_hint: Some(hint.to_string()),
        }
    }

    fn cves(findings: &[Finding]) -> Vec<String> {
        findings.iter().map(|f| f.cve.clone()).collect()
    }

    #[test]
    fn db_merges_curated_json_with_sqlite() {
        let db = load_db();
        assert!(!db.is_empty());
        assert!(
            std::ptr::eq(db.as_ptr(), load_db().as_ptr()),
            "load_db debe estar cacheada"
        );
        // Las reglas curadas traen rangos de version, que la SQLite no guarda.
        let ssh = db.iter().find(|e| e.cve == "CVE-2018-15473").unwrap();
        assert_eq!(ssh.match_versions.len(), 1);
        // No hay CVEs repetidos entre JSON y SQLite
        let unique: HashSet<&String> = db.iter().map(|e| &e.cve).collect();
        assert_eq!(unique.len(), db.len());
    }

    #[test]
    fn ssh_version_range_flags_affected_only() {
        let viejo = port(22, Some("SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10"), "SSH");
        let hallados = cves(&check_port(&viejo, load_db()));
        assert!(
            hallados.contains(&"CVE-2018-15473".to_string()),
            "{hallados:?}"
        );
        assert!(
            !hallados.contains(&"CVE-2023-38408".to_string()),
            "{hallados:?}"
        );

        let nuevo = port(22, Some("SSH-2.0-OpenSSH_9.6p1"), "SSH");
        let hallados = cves(&check_port(&nuevo, load_db()));
        assert!(
            hallados.is_empty(),
            "9.6 no esta en ningun rango: {hallados:?}"
        );

        let intermedio = port(22, Some("SSH-2.0-OpenSSH_9.3p1"), "SSH");
        let hallados = cves(&check_port(&intermedio, load_db()));
        assert!(
            hallados.contains(&"CVE-2023-38408".to_string()),
            "{hallados:?}"
        );
    }

    #[test]
    fn smb_needs_the_smb1_negotiation_not_just_the_port() {
        // 445 abierto negociando SMB2: NO es EternalBlue
        let moderno = port(445, Some("SMB2/3"), "SMB");
        assert!(cves(&check_port(&moderno, load_db())).is_empty());
        // 445 abierto sin poder negociar: tampoco se afirma nada
        let desconocido = port(445, None, "SMB");
        assert!(cves(&check_port(&desconocido, load_db())).is_empty());
        // 445 que acepta SMB1: exposicion real
        let viejo = port(445, Some("SMB1 habilitado"), "SMB");
        assert!(cves(&check_port(&viejo, load_db())).contains(&"CVE-2017-0144".to_string()));
    }

    #[test]
    fn rdp_port_only_is_flagged_as_suspicion() {
        let rdp = port(3389, None, "RDP");
        assert!(cves(&check_port(&rdp, load_db())).contains(&"CVE-2019-0708".to_string()));
    }

    #[test]
    fn http_requires_the_banner() {
        let nginx = port(80, Some("nginx/1.18.0"), "HTTP");
        assert!(cves(&check_port(&nginx, load_db())).is_empty());
        let vulnerable = port(80, Some("Apache/2.4.49 (Unix)"), "HTTP");
        assert!(cves(&check_port(&vulnerable, load_db())).contains(&"CVE-2021-44228".to_string()));
    }

    #[test]
    fn findings_are_sorted_by_severity_and_deduped() {
        let ports = [
            port(22, Some("SSH-2.0-OpenSSH_7.2p2"), "SSH"),
            port(445, Some("SMB1 habilitado"), "SMB"),
        ];
        let findings = check_host(&ports);
        assert!(findings.len() >= 2);
        assert_eq!(findings[0].severity, "critica");
        let unique: HashSet<(String, u16)> =
            findings.iter().map(|f| (f.cve.clone(), f.port)).collect();
        assert_eq!(unique.len(), findings.len(), "sin hallazgos repetidos");
    }
}
