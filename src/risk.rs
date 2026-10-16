//! Score de riesgo por host.
//!
//! Una lista de hallazgos no dice por donde empezar. Este modulo combina
//! severidad (y su certeza) con la exposicion de servicios para dar un numero
//! 0-100, un nivel y las razones: lo critico deja de quedar enterrado en la
//! fila 40 de una tabla ordenada por IP.

use crate::network::HostInfo;
use serde::Serialize;

const W_CRITICA: u32 = 40;
const W_ALTA: u32 = 25;
const W_MEDIA: u32 = 12;
const W_BAJA: u32 = 5;
const MAX_SCORE: u32 = 100;

/// Servicios que suman riesgo por si mismos cuando estan expuestos.
const EXPOSURE: &[(u16, u32, &str)] = &[
    (3389, 15, "RDP expuesto"),
    (23, 15, "Telnet en claro"),
    (5900, 12, "VNC expuesto"),
    (445, 10, "SMB expuesto"),
    (3306, 10, "MySQL expuesto"),
    (5432, 10, "PostgreSQL expuesto"),
    (21, 8, "FTP en claro"),
    (135, 5, "MSRPC expuesto"),
    (139, 5, "NetBIOS expuesto"),
    (1723, 5, "PPTP obsoleto"),
];

#[derive(Debug, Clone, Serialize)]
pub struct RiskScore {
    pub score: u32,
    pub level: &'static str,
    pub reasons: Vec<String>,
}

impl RiskScore {
    fn level_for(score: u32) -> &'static str {
        match score {
            60.. => "critico",
            40..=59 => "alto",
            20..=39 => "medio",
            1..=19 => "bajo",
            _ => "sin riesgo",
        }
    }
}

pub fn score_host(host: &HostInfo) -> RiskScore {
    let mut score = 0u32;
    let mut reasons: Vec<String> = Vec::new();

    for f in &host.vulnerabilities {
        let (peso, motivo) = match (f.severity.as_str(), f.confidence.as_str()) {
            ("critica", "confirmado") => (W_CRITICA, "critica confirmada"),
            ("critica", _) => (W_CRITICA - 10, "critica sin confirmar"),
            ("alta", "confirmado") => (W_ALTA, "alta confirmada"),
            ("alta", _) => (W_ALTA - 7, "alta sin confirmar"),
            ("media", _) => (W_MEDIA, "media"),
            _ => (W_BAJA, "baja"),
        };
        score += peso;
        reasons.push(format!("{} {} en :{}", f.cve, motivo, f.port));
    }

    for (port, peso, motivo) in EXPOSURE {
        if host.open_ports.iter().any(|p| p.port == *port) {
            score += peso;
            reasons.push(format!("{} :{}", motivo, port));
        }
    }

    score = score.min(MAX_SCORE);
    RiskScore {
        score,
        level: RiskScore::level_for(score),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::PortResult;
    use crate::vuln::Finding;

    fn host_with(ports: Vec<u16>, vulns: Vec<(&str, &str, &str, u16)>) -> HostInfo {
        HostInfo {
            ip: "192.168.1.50".to_string(),
            hostname: None,
            mac: Some("24:a6:5e:00:00:01".to_string()),
            vendor: None,
            vendor_source: None,
            is_alive: true,
            open_ports: ports
                .into_iter()
                .map(|p| PortResult {
                    port: p,
                    state: "open".to_string(),
                    banner: None,
                    service_hint: None,
                })
                .collect(),
            latency_ms: None,
            vulnerabilities: vulns
                .into_iter()
                .map(|(cve, sev, conf, port)| Finding {
                    cve: cve.to_string(),
                    severity: sev.to_string(),
                    port,
                    service: "test".to_string(),
                    banner: None,
                    confidence: conf.to_string(),
                    evidence: None,
                    description: String::new(),
                    recommendation: String::new(),
                })
                .collect(),
            mdns_names: Vec::new(),
            ssdp_location: None,
        }
    }

    #[test]
    fn clean_host_has_no_risk() {
        let r = score_host(&host_with(vec![], vec![]));
        assert_eq!(r.score, 0);
        assert_eq!(r.level, "sin riesgo");
        assert!(r.reasons.is_empty());
    }

    #[test]
    fn confirmed_critical_plus_exposure_is_critical() {
        let r = score_host(&host_with(
            vec![445, 3389],
            vec![("CVE-2017-0144", "critica", "confirmado", 445)],
        ));
        assert_eq!(r.score, 40 + 10 + 15);
        assert_eq!(r.level, "critico");
        assert!(r.reasons.iter().any(|x| x.contains("CVE-2017-0144")));
        assert!(r.reasons.iter().any(|x| x.contains("RDP expuesto")));
    }

    #[test]
    fn unconfirmed_weighs_less_than_confirmed() {
        let confirmado = score_host(&host_with(
            vec![],
            vec![("C", "critica", "confirmado", 445)],
        ));
        let sospecha = score_host(&host_with(vec![], vec![("C", "critica", "sospecha", 445)]));
        assert!(confirmado.score > sospecha.score);
        assert_ne!(
            sospecha.level, "critico",
            "sin confirmar no puede ser critico"
        );
        assert_eq!(sospecha.level, "medio");
    }

    #[test]
    fn score_is_capped_and_levels_are_ordered() {
        let muchos = host_with(
            vec![3389, 23, 5900, 445, 3306, 5432, 21, 135, 139, 1723],
            vec![
                ("A", "critica", "confirmado", 445),
                ("B", "critica", "confirmado", 445),
                ("C", "alta", "confirmado", 22),
            ],
        );
        assert_eq!(score_host(&muchos).score, MAX_SCORE);
        assert_eq!(RiskScore::level_for(0), "sin riesgo");
        assert_eq!(RiskScore::level_for(19), "bajo");
        assert_eq!(RiskScore::level_for(20), "medio");
        assert_eq!(RiskScore::level_for(40), "alto");
        assert_eq!(RiskScore::level_for(60), "critico");
    }
}
