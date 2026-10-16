//! Historial de escaneos: convierte fotos sueltas en vigilancia.
//!
//! Guarda cada escaneo con sus dispositivos y calcula la diferencia contra el
//! anterior: dispositivo nuevo, desaparecido y puerto que se abrió. Además
//! detecta anomalías de capa 2 con datos que ya tenemos: la misma MAC en varias
//! IP (virtualización o ARP spoofing) y la MAC del gateway cambiada (posible
//! MitM).

use crate::network::HostInfo;
use chrono::Utc;
use rusqlite::{Connection, params};
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;

/// Cuántos escaneos se conservan (los más viejos se purgan).
const KEEP_SCANS: i64 = 200;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Event {
    /// `nuevo` | `desaparecido` | `puerto_nuevo` | `mac_duplicada` | `gateway_cambio`
    pub kind: String,
    pub ip: String,
    pub mac: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
struct DeviceRow {
    mac: Option<String>,
    ports: Vec<u16>,
}

pub struct History {
    conn: Connection,
}

fn ip_key(ip: &str) -> u32 {
    ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(u32::MAX)
}

/// Gateway por heurística: la IP más baja vista en la red (casi siempre .1).
fn gateway_ip(hosts: &[HostInfo]) -> Option<String> {
    hosts
        .iter()
        .map(|h| h.ip.clone())
        .min_by_key(|ip| ip_key(ip))
}

impl History {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("no se pudo abrir {}: {e}", path.display()))?;
        Self::from_conn(conn)
    }

    fn from_conn(conn: Connection) -> Result<Self, String> {
        let hist = History { conn };
        hist.migrate()?;
        Ok(hist)
    }

    fn migrate(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS scans (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts TEXT NOT NULL,
                   subnet TEXT,
                   hosts INTEGER NOT NULL,
                   vulns INTEGER NOT NULL,
                   duration_s REAL NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS devices (
                   scan_id INTEGER NOT NULL,
                   ip TEXT NOT NULL,
                   mac TEXT,
                   hostname TEXT,
                   vendor TEXT,
                   vendor_source TEXT,
                   ports TEXT NOT NULL,
                   vulns INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS idx_devices_scan ON devices(scan_id);",
            )
            .map_err(|e| format!("migracion: {e}"))
    }

    /// Id del último escaneo guardado.
    pub fn last_scan_id(&self) -> Option<i64> {
        self.conn
            .query_row("SELECT id FROM scans ORDER BY id DESC LIMIT 1", [], |r| {
                r.get(0)
            })
            .ok()
    }

    pub fn scan_count(&self) -> i64 {
        self.conn
            .query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
            .unwrap_or(0)
    }

    fn devices_of(&self, scan_id: i64) -> HashMap<String, DeviceRow> {
        let mut out = HashMap::new();
        let Ok(mut stmt) = self
            .conn
            .prepare("SELECT ip, mac, ports FROM devices WHERE scan_id = ?1")
        else {
            return out;
        };
        let rows = stmt.query_map(params![scan_id], |row| {
            let ip: String = row.get(0)?;
            let mac: Option<String> = row.get(1)?;
            let ports: String = row.get(2)?;
            Ok((ip, mac, ports))
        });
        if let Ok(rows) = rows {
            for (ip, mac, ports) in rows.flatten() {
                let ports = ports
                    .split(',')
                    .filter_map(|p| p.trim().parse::<u16>().ok())
                    .collect();
                out.insert(ip, DeviceRow { mac, ports });
            }
        }
        out
    }

    /// Guarda el escaneo actual y devuelve los eventos contra `previous`.
    pub fn diff_and_record(
        &self,
        previous: Option<i64>,
        hosts: &[HostInfo],
        subnet: Option<&str>,
        duration_secs: f64,
    ) -> Vec<Event> {
        let before = previous.map(|id| self.devices_of(id)).unwrap_or_default();
        let mut events = Vec::new();

        if previous.is_some() && !before.is_empty() {
            for h in hosts {
                match before.get(&h.ip) {
                    None => {
                        let extra = match h.vendor_source.as_deref() {
                            Some("oui-local") => " (MAC aleatoria/local)".to_string(),
                            _ => h
                                .vendor
                                .clone()
                                .map(|v| format!(" ({v})"))
                                .unwrap_or_default(),
                        };
                        events.push(Event {
                            kind: "nuevo".to_string(),
                            ip: h.ip.clone(),
                            mac: h.mac.clone(),
                            detail: format!("dispositivo nuevo{extra}"),
                        });
                    }
                    Some(prev) => {
                        let nuevos: Vec<u16> = h
                            .open_ports
                            .iter()
                            .map(|p| p.port)
                            .filter(|p| !prev.ports.contains(p))
                            .collect();
                        if !nuevos.is_empty() {
                            let lista = nuevos
                                .iter()
                                .map(|p| p.to_string())
                                .collect::<Vec<_>>()
                                .join(", ");
                            events.push(Event {
                                kind: "puerto_nuevo".to_string(),
                                ip: h.ip.clone(),
                                mac: h.mac.clone(),
                                detail: format!("puertos nuevos: {lista}"),
                            });
                        }
                    }
                }
            }
            for (ip, prev) in &before {
                if !hosts.iter().any(|h| h.ip == *ip) {
                    events.push(Event {
                        kind: "desaparecido".to_string(),
                        ip: ip.clone(),
                        mac: prev.mac.clone(),
                        detail: "ya no responde".to_string(),
                    });
                }
            }
        }

        events.extend(Self::anomalies(hosts, &before));

        if let Err(e) = self.record(hosts, subnet, duration_secs) {
            eprintln!("historial: no se pudo guardar el escaneo: {e}");
        }
        events
    }

    /// Anomalías de capa 2 con los datos ya recolectados.
    fn anomalies(hosts: &[HostInfo], before: &HashMap<String, DeviceRow>) -> Vec<Event> {
        let mut events = Vec::new();

        let mut por_mac: HashMap<String, Vec<String>> = HashMap::new();
        for h in hosts {
            if let Some(mac) = h.mac.as_ref() {
                por_mac.entry(mac.clone()).or_default().push(h.ip.clone());
            }
        }
        for (mac, ips) in &por_mac {
            if ips.len() > 1 {
                events.push(Event {
                    kind: "mac_duplicada".to_string(),
                    ip: ips.join(", "),
                    mac: Some(mac.clone()),
                    detail: format!(
                        "la misma MAC aparece en {} IPs: ARP spoofing o virtualizacion",
                        ips.len()
                    ),
                });
            }
        }

        if let Some(gw) = gateway_ip(hosts) {
            let actual = hosts
                .iter()
                .find(|h| h.ip == gw)
                .and_then(|h| h.mac.clone());
            let anterior = before.get(&gw).and_then(|d| d.mac.clone());
            if let (Some(a), Some(b)) = (actual, anterior) {
                if a != b {
                    events.push(Event {
                        kind: "gateway_cambio".to_string(),
                        ip: gw,
                        mac: Some(a),
                        detail: format!(
                            "la MAC del gateway cambio de {b} a un valor nuevo: posible MitM"
                        ),
                    });
                }
            }
        }

        events
    }

    fn record(
        &self,
        hosts: &[HostInfo],
        subnet: Option<&str>,
        duration_secs: f64,
    ) -> Result<i64, String> {
        let vulns: i64 = hosts.iter().map(|h| h.vulnerabilities.len() as i64).sum();
        self.conn
            .execute(
                "INSERT INTO scans (ts, subnet, hosts, vulns, duration_s) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![Utc::now().to_rfc3339(), subnet, hosts.len() as i64, vulns, duration_secs],
            )
            .map_err(|e| e.to_string())?;
        let scan_id = self.conn.last_insert_rowid();

        {
            let mut stmt = self
                .conn
                .prepare(
                    "INSERT INTO devices (scan_id, ip, mac, hostname, vendor, vendor_source, ports, vulns)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )
                .map_err(|e| e.to_string())?;
            for h in hosts {
                let ports = h
                    .open_ports
                    .iter()
                    .map(|p| p.port.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                stmt.execute(params![
                    scan_id,
                    h.ip,
                    h.mac,
                    h.hostname,
                    h.vendor,
                    h.vendor_source,
                    ports,
                    h.vulnerabilities.len() as i64
                ])
                .map_err(|e| e.to_string())?;
            }
        }

        // Poda: la historia se acota a los ultimos KEEP_SCANS escaneos.
        self.conn
            .execute(
                "DELETE FROM devices WHERE scan_id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?1)",
                params![KEEP_SCANS],
            )
            .ok();
        self.conn
            .execute(
                "DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?1)",
                params![KEEP_SCANS],
            )
            .ok();
        Ok(scan_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::PortResult;

    fn host(ip: &str, mac: Option<&str>, ports: &[u16]) -> HostInfo {
        HostInfo {
            ip: ip.to_string(),
            hostname: None,
            mac: mac.map(|m| m.to_string()),
            vendor: None,
            vendor_source: None,
            is_alive: true,
            open_ports: ports
                .into_iter()
                .map(|p| PortResult {
                    port: *p,
                    state: "open".to_string(),
                    banner: None,
                    service_hint: None,
                })
                .collect(),
            latency_ms: None,
            vulnerabilities: Vec::new(),
            mdns_names: Vec::new(),
            ssdp_location: None,
        }
    }

    fn mem() -> History {
        History::from_conn(Connection::open_in_memory().unwrap()).unwrap()
    }

    #[test]
    fn first_scan_records_without_events() {
        let h = mem();
        let hosts = vec![host("192.168.1.10", Some("aa:bb:cc:dd:ee:01"), &[80])];
        let events = h.diff_and_record(None, &hosts, Some("192.168.1.0/24"), 1.0);
        assert!(
            events.is_empty(),
            "sin escaneo previo no hay nada que comparar"
        );
        assert_eq!(h.scan_count(), 1);
        assert!(h.last_scan_id().is_some());
    }

    #[test]
    fn detects_new_gone_and_new_ports() {
        let h = mem();
        let primero = vec![
            host("192.168.1.10", Some("aa:bb:cc:dd:ee:01"), &[80]),
            host("192.168.1.11", Some("aa:bb:cc:dd:ee:02"), &[22]),
        ];
        h.diff_and_record(None, &primero, None, 1.0);
        let prev = h.last_scan_id();

        let segundo = vec![
            host("192.168.1.11", Some("aa:bb:cc:dd:ee:02"), &[22, 445]),
            host("192.168.1.12", Some("aa:bb:cc:dd:ee:03"), &[]),
        ];
        let eventos = h.diff_and_record(prev, &segundo, None, 1.0);
        let kinds: Vec<&str> = eventos.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"desaparecido"), "{eventos:?}");
        assert!(kinds.contains(&"nuevo"), "{eventos:?}");
        assert!(kinds.contains(&"puerto_nuevo"), "{eventos:?}");
        let puerto = eventos.iter().find(|e| e.kind == "puerto_nuevo").unwrap();
        assert_eq!(puerto.ip, "192.168.1.11");
        assert!(puerto.detail.contains("445"));
        let nuevo = eventos.iter().find(|e| e.kind == "nuevo").unwrap();
        assert_eq!(nuevo.ip, "192.168.1.12");
    }

    #[test]
    fn detects_duplicated_mac() {
        let h = mem();
        let hosts = vec![
            host("192.168.1.10", Some("02:00:5e:10:00:02"), &[]),
            host("192.168.1.11", Some("02:00:5e:10:00:02"), &[]),
            host("192.168.1.12", Some("24:a6:5e:00:00:01"), &[]),
        ];
        let eventos = h.diff_and_record(None, &hosts, None, 1.0);
        let dup: Vec<_> = eventos
            .iter()
            .filter(|e| e.kind == "mac_duplicada")
            .collect();
        assert_eq!(dup.len(), 1, "{eventos:?}");
        assert!(dup[0].detail.contains("2 IPs"));
        assert_eq!(dup[0].mac.as_deref(), Some("02:00:5e:10:00:02"));
    }

    #[test]
    fn detects_gateway_mac_change() {
        let h = mem();
        // El gateway es la IP mas baja vista (heuristica .1)
        let primero = vec![
            host("192.168.1.1", Some("24:a6:5e:00:00:01"), &[80]),
            host("192.168.1.20", Some("aa:bb:cc:dd:ee:20"), &[]),
        ];
        h.diff_and_record(None, &primero, None, 1.0);
        let prev = h.last_scan_id();

        let segundo = vec![
            host("192.168.1.1", Some("de:ad:be:ef:00:01"), &[80]),
            host("192.168.1.20", Some("aa:bb:cc:dd:ee:20"), &[]),
        ];
        let eventos = h.diff_and_record(prev, &segundo, None, 1.0);
        let cambio = eventos
            .iter()
            .find(|e| e.kind == "gateway_cambio")
            .expect("debe detectar el cambio");
        assert_eq!(cambio.ip, "192.168.1.1");
        assert!(cambio.detail.contains("MitM"));
    }

    #[test]
    fn keeps_only_the_last_scans() {
        let h = mem();
        for i in 0..(KEEP_SCANS + 3) {
            let ip = format!("192.168.1.{}", (i % 200) + 2);
            h.diff_and_record(None, &[host(&ip, None, &[])], None, 0.1);
        }
        assert_eq!(h.scan_count(), KEEP_SCANS, "la historia se poda");
    }
}
