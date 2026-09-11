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

pub fn load_db() -> Vec<VulnEntry> {
    serde_json::from_str(DB_JSON).unwrap_or_default()
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
