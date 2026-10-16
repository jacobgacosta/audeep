//! Configuracion opcional (`audeep.json`).
//!
//! Sin dependencias nuevas: es JSON y se lee con serde_json, que ya esta en el
//! proyecto. Todo campo es opcional; el archivo solo pisa lo que declara.

use crate::scanner::COMMON_PORTS;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_FILE: &str = "audeep.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Timeout de conexion por puerto/host, en ms.
    #[serde(default = "default_timeout")]
    pub probe_timeout_ms: u64,
    /// Tareas de red en paralelo.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// Ventana de escucha de mDNS/SSDP, en ms.
    #[serde(default = "default_mdns")]
    pub mdns_timeout_ms: u64,
    /// Puertos a escanear (por defecto los 21 comunes).
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
    /// IPs a excluir del reporte (equipos propios, impresoras que se caen, etc).
    #[serde(default)]
    pub exclude: Vec<String>,
}

fn default_timeout() -> u64 {
    400
}

fn default_concurrency() -> usize {
    64
}

fn default_mdns() -> u64 {
    1200
}

fn default_ports() -> Vec<u16> {
    COMMON_PORTS.to_vec()
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            probe_timeout_ms: default_timeout(),
            concurrency: default_concurrency(),
            mdns_timeout_ms: default_mdns(),
            ports: default_ports(),
            exclude: Vec::new(),
        }
    }
}

impl AuditConfig {
    /// Carga la config: el archivo de `--config` si se paso, si no `audeep.json`
    /// del directorio actual cuando existe. Devuelve tambien de donde salio.
    pub fn load(explicit: Option<&Path>) -> Result<(Self, Option<PathBuf>), String> {
        match explicit {
            Some(p) => Ok((Self::from_file(p)?, Some(p.to_path_buf()))),
            None => {
                let auto = PathBuf::from(DEFAULT_CONFIG_FILE);
                if auto.exists() {
                    Ok((Self::from_file(&auto)?, Some(auto)))
                } else {
                    Ok((Self::default(), None))
                }
            }
        }
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("no se pudo leer {}: {e}", path.display()))?;
        let mut cfg: Self = serde_json::from_str(&text)
            .map_err(|e| format!("JSON invalido en {}: {e}", path.display()))?;
        cfg.normalize();
        Ok(cfg)
    }

    /// Deja los valores dentro de rangos usables: un timeout de 0 ms o 5000
    /// tareas paralelas rompen el escaneo.
    fn normalize(&mut self) {
        if self.ports.is_empty() {
            self.ports = default_ports();
        }
        self.ports.sort_unstable();
        self.ports.dedup();
        self.probe_timeout_ms = self.probe_timeout_ms.clamp(50, 10_000);
        self.mdns_timeout_ms = self.mdns_timeout_ms.clamp(0, 10_000);
        self.concurrency = self.concurrency.clamp(1, 512);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(name: &str, content: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("audeep_cfg_{}_{name}.json", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn defaults_match_the_scanner() {
        let cfg = AuditConfig::default();
        assert_eq!(cfg.probe_timeout_ms, 400);
        assert_eq!(cfg.concurrency, 64);
        assert_eq!(cfg.ports, COMMON_PORTS.to_vec());
        assert!(cfg.exclude.is_empty());
    }

    #[test]
    fn partial_json_only_overrides_what_it_declares() {
        let path = temp_file(
            "partial",
            r#"{"probe_timeout_ms":250,"exclude":["192.168.1.1"]}"#,
        );
        let cfg = AuditConfig::from_file(&path).unwrap();
        assert_eq!(cfg.probe_timeout_ms, 250);
        assert_eq!(cfg.concurrency, 64, "lo no declarado queda por defecto");
        assert_eq!(cfg.ports, COMMON_PORTS.to_vec());
        assert_eq!(cfg.exclude, vec!["192.168.1.1".to_string()]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn normalize_fixes_absurd_values() {
        let path = temp_file(
            "absurd",
            r#"{"ports":[443,80,80],"concurrency":0,"probe_timeout_ms":1}"#,
        );
        let cfg = AuditConfig::from_file(&path).unwrap();
        assert_eq!(cfg.ports, vec![80, 443], "ordenado y sin repetidos");
        assert_eq!(cfg.concurrency, 1);
        assert_eq!(cfg.probe_timeout_ms, 50);
        let _ = std::fs::remove_file(path);

        let vacio = temp_file("vacio", r#"{"ports":[]}"#);
        assert_eq!(
            AuditConfig::from_file(&vacio).unwrap().ports,
            COMMON_PORTS.to_vec()
        );
        let _ = std::fs::remove_file(vacio);
    }

    #[test]
    fn load_autodetects_or_reports_errors() {
        // Un --config inexistente es un error explicito
        let missing = std::env::temp_dir().join("audeep_cfg_no_existe_12345.json");
        assert!(AuditConfig::load(Some(&missing)).is_err());

        // JSON roto tambien
        let roto = temp_file("roto", "{no soy json");
        assert!(AuditConfig::from_file(&roto).is_err());
        let _ = std::fs::remove_file(roto);

        // Sin --config y sin audeep.json: defaults y fuente None
        let (cfg, fuente) = AuditConfig::load(None).unwrap();
        if !PathBuf::from(DEFAULT_CONFIG_FILE).exists() {
            assert!(fuente.is_none());
            assert_eq!(cfg.probe_timeout_ms, 400);
        }
    }
}
