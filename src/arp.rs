//! Tabla ARP: lectura y parseo robusto multi-formato.
//!
//! Windows (`arp -a`) y Linux (`/proc/net/arp`) usan columnas distintas, y el
//! texto de Windows viene localizado (`dynamic`/`dinámico`, `static`/`estático`),
//! así que el parser no asume posición de columna ni idioma: exige que la primera
//! columna sea una IPv4 y busca el primer token con forma de MAC en las siguientes.
//!
//! También valida que la MAC sean 6 octetos hexadecimales, para que una línea de
//! encabezado o de basura no contamine el mapa.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

pub const ZERO_MAC: &str = "00:00:00:00:00:00";
pub const BROADCAST_MAC: &str = "ff:ff:ff:ff:ff:ff";

/// Normaliza a minúsculas con separador `:`.
/// Devuelve `None` si no son 6 octetos hexadecimales.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let mac = raw.trim().replace('-', ":").to_lowercase();
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    if !parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(mac)
}

/// `true` si la MAC es de administración local (bit `0x02` del primer octeto):
/// no identifica al fabricante real (Wi-Fi aleatorio, VMs, Docker, WSL).
pub fn is_locally_administered(mac: &str) -> bool {
    mac.split(':')
        .next()
        .and_then(|o| u8::from_str_radix(o, 16).ok())
        .map(|b| b & 0x02 != 0)
        .unwrap_or(false)
}

/// Parsea la salida de `arp -a` (Windows) o el contenido de `/proc/net/arp` (Linux).
pub fn parse_arp_table(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        // Solo IPv4 y solo direcciones unicast: multicast/broadcast no son hosts.
        let Ok(v4) = parts[0].parse::<Ipv4Addr>() else {
            continue;
        };
        if v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified() {
            continue;
        }
        // Windows: MAC en la columna 1. Linux: MAC en la columna 3.
        let Some(mac) = parts.iter().take(4).find_map(|t| normalize_mac(t)) else {
            continue;
        };
        if mac == ZERO_MAC || mac == BROADCAST_MAC {
            continue;
        }
        map.insert(IpAddr::V4(v4).to_string(), mac);
    }
    map
}

#[cfg(target_os = "windows")]
fn read_arp_text() -> Option<String> {
    let out = std::process::Command::new("arp").arg("-a").output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(not(target_os = "windows"))]
fn read_arp_text() -> Option<String> {
    std::fs::read_to_string("/proc/net/arp").ok()
}

/// Foto de la tabla ARP del sistema (solo lectura, sin raw sockets ni permisos extra).
pub fn arp_table_snapshot() -> HashMap<String, String> {
    read_arp_text()
        .map(|t| parse_arp_table(&t))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOWS_EN: &str = "Interface: 192.168.1.7 --- 0xf\n  Internet Address      Physical Address      Type\n  192.168.1.1           24-a6-5e-00-00-01     dynamic\n  224.0.0.22            01-00-5e-00-00-16     static\n  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n  192.168.1.50          02-00-5e-10-00-02     dynamic\n";

    const WINDOWS_ES: &str = "Interfaz: 192.168.1.7 --- 0xf\n  Dirección de Internet  Dirección física      Tipo\n  192.168.1.20          88-f4-da-00-00-03     dinámico\n  192.168.1.21          48-b0-2d-33-44-55     estático\n";

    const LINUX: &str = "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.1      0x1         0x2         24:a6:5e:00:00:01     *        eth0\n192.168.1.50     0x1         0x2         02:00:5e:10:00:02     *        eth0\n0.0.0.0          0x1         0x0         00:00:00:00:00:00     *        eth0\n";

    #[test]
    fn windows_english_filters_multicast_and_broadcast() {
        let m = parse_arp_table(WINDOWS_EN);
        assert_eq!(
            m.get("192.168.1.1").map(String::as_str),
            Some("24:a6:5e:00:00:01")
        );
        assert_eq!(
            m.get("192.168.1.50").map(String::as_str),
            Some("02:00:5e:10:00:02")
        );
        assert!(!m.contains_key("224.0.0.22"), "multicast no es un host");
        assert!(!m.contains_key("192.168.1.255"), "broadcast no es un host");
        assert_eq!(m.len(), 2, "solo 2 entradas validas");
    }

    #[test]
    fn windows_spanish_headers_and_type_ignored() {
        let m = parse_arp_table(WINDOWS_ES);
        assert_eq!(m.len(), 2);
        assert_eq!(
            m.get("192.168.1.20").map(String::as_str),
            Some("88:f4:da:00:00:03")
        );
        assert_eq!(
            m.get("192.168.1.21").map(String::as_str),
            Some("48:b0:2d:33:44:55")
        );
    }

    #[test]
    fn linux_proc_format_uses_third_column() {
        let m = parse_arp_table(LINUX);
        assert_eq!(m.len(), 2);
        assert_eq!(
            m.get("192.168.1.50").map(String::as_str),
            Some("02:00:5e:10:00:02")
        );
    }

    #[test]
    fn garbage_never_enters() {
        for bad in [
            "no soy arp",
            "192.168.1.1 zz-zz-zz-zz-zz-zz dynamic",
            "192.168.1.1 aa-bb-cc dynamic",
            "999.1.1.1 aa-bb-cc-dd-ee-ff dynamic",
            "",
            "   ",
        ] {
            assert!(parse_arp_table(bad).is_empty(), "entro basura: {bad:?}");
        }
    }

    #[test]
    fn mac_normalization_and_virtual_bit() {
        assert_eq!(
            normalize_mac("24-A6-5E-00-00-01").as_deref(),
            Some("24:a6:5e:00:00:01")
        );
        assert_eq!(normalize_mac("24:a6:5e:00:00"), None);
        // 0x9a = 1001_1010 -> bit 0x02 prendido: MAC local/aleatoria.
        assert!(is_locally_administered("02:00:5e:10:00:02"));
        assert!(!is_locally_administered("24:a6:5e:00:00:01"));
    }
}
