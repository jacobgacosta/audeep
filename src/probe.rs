//! Sondas activas de confirmación.
//!
//! Ver "el puerto 445 abierto" no dice nada: dice que hay algo escuchando. Lo
//! que decide si hay exposición real es el **protocolo que negocia** ese
//! servicio. Acá se negocia SMB1 de verdad y se parsea el banner de SSH para
//! compararlo contra rangos de versión, todo sin dependencias y sin exploits.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// SMB1 `Negotiate Protocol` de 73 bytes: header NetBIOS (4) + header SMB (32)
/// + WordCount (1) + ByteCount (2) + dialectos (34).
///
/// Los dialectos ofrecidos son `NT LM 0.12` (SMB1), `SMB 2.002` y `SMB 2.???`,
/// así que un servidor moderno responde con SMB2 y uno viejo con SMB1: la
/// respuesta dice cuál acepta.
pub fn smb1_negotiate_request() -> Vec<u8> {
    let dialects: [&[u8]; 3] = [
        b"\x02NT LM 0.12\x00",
        b"\x02SMB 2.002\x00",
        b"\x02SMB 2.???\x00",
    ];

    let mut body: Vec<u8> = Vec::with_capacity(69);
    body.extend_from_slice(&[0xFF, b'S', b'M', b'B', 0x72]); // \xFFSMB + Negotiate Protocol
    body.extend_from_slice(&[0, 0, 0, 0]); // status
    body.extend_from_slice(&[0x18, 0x53, 0xC8]); // flags + flags2
    body.extend_from_slice(&[0, 0]); // pid high
    body.extend_from_slice(&[0u8; 8]); // signature
    body.extend_from_slice(&[0, 0, 0, 0]); // reserved + tid
    body.extend_from_slice(&[0xFF, 0xFE]); // pid
    body.extend_from_slice(&[0, 0, 0, 0]); // uid + mid
    body.push(0x00); // word count

    let byte_count: u16 = dialects.iter().map(|d| d.len() as u16).sum();
    body.extend_from_slice(&byte_count.to_le_bytes());
    for d in dialects {
        body.extend_from_slice(d);
    }

    let mut pkt = Vec::with_capacity(body.len() + 4);
    let len = body.len() as u16;
    pkt.extend_from_slice(&[0, 0, (len >> 8) as u8, (len & 0xFF) as u8]);
    pkt.extend_from_slice(&body);
    pkt
}

/// Dialecto que aceptó el servidor, a partir de la respuesta de negociación.
/// `0xFE` = `\xFESMB` (SMB2/3), `0xFF` = `\xFFSMB` (SMB1).
pub fn smb_dialect(resp: &[u8]) -> Option<&'static str> {
    if resp.len() < 8 {
        return None;
    }
    match resp[4] {
        0xFE => Some("SMB2/3"),
        0xFF => Some("SMB1"),
        _ => None,
    }
}

/// `true` si el 445 negocia SMB1 (protocolo obsoleto: exposición a EternalBlue),
/// `false` si solo SMB2/3, `None` si no se pudo determinar.
pub async fn smb1_enabled(ip: IpAddr, timeout_ms: u64) -> Option<bool> {
    let addr = SocketAddr::new(ip, 445);
    let mut stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let req = smb1_negotiate_request();
    timeout(Duration::from_millis(timeout_ms), stream.write_all(&req))
        .await
        .ok()?
        .ok()?;
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    match smb_dialect(&buf[..n])? {
        "SMB1" => Some(true),
        _ => Some(false),
    }
}

/// Producto y versión de un banner SSH (`SSH-2.0-OpenSSH_7.2p2 Ubuntu`).
pub fn parse_ssh_banner(banner: &str) -> Option<(String, String)> {
    let line = banner.lines().next()?.trim();
    let rest = line.strip_prefix("SSH-")?;
    let mut parts = rest.splitn(2, '-');
    let _protocol = parts.next()?;
    let software = parts.next()?.trim();
    match software.rsplit_once('_') {
        // El banner trae comentarios de distro: la version es el primer token.
        Some((product, rest)) => Some((
            product.to_string(),
            rest.split_whitespace().next().unwrap_or("").to_string(),
        )),
        None => Some((software.to_string(), String::new())),
    }
}

/// Clave de versión `[mayor, menor]`.
///
/// El nivel de parche se ignora a propósito: los rangos de los avisos se
/// publican por `mayor.menor` y sin conocer el parche exacto no se puede
/// afirmar más. Por eso un acierto por rango es "probable" y no "confirmado".
pub fn version_key(version: &str) -> [u32; 2] {
    let mut out = [0u32; 2];
    for (i, part) in version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .take(2)
        .enumerate()
    {
        out[i] = part.parse().unwrap_or(0);
    }
    out
}

/// `true` si `version` cae dentro de `[min, max]` (inclusive).
pub fn version_in_range(version: &str, min: &str, max: &str) -> bool {
    if version.trim().is_empty() {
        return false;
    }
    let v = version_key(version);
    v >= version_key(min) && v <= version_key(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb1_request_is_the_expected_73_bytes() {
        let req = smb1_negotiate_request();
        assert_eq!(req.len(), 73, "tamano del Negotiate Protocol");
        // NetBIOS session header: 69 bytes de SMB a continuacion
        assert_eq!(&req[0..4], &[0, 0, 0, 69]);
        // Firma SMB1 + comando Negotiate Protocol
        assert_eq!(&req[4..8], &[0xFF, b'S', b'M', b'B']);
        assert_eq!(req[8], 0x72);
        // ByteCount = suma de dialectos (12 + 11 + 11)
        assert_eq!(&req[37..39], &[34, 0]);
        assert!(req.ends_with(b"SMB 2.???\x00"));
    }

    #[test]
    fn smb_dialect_reads_protocol_magic() {
        let smb2 = [0x00, 0x00, 0x00, 0xAA, 0xFE, b'S', b'M', b'B', 0x40, 0x00];
        assert_eq!(smb_dialect(&smb2), Some("SMB2/3"));
        let smb1 = [0x00, 0x00, 0x00, 0x2A, 0xFF, b'S', b'M', b'B', 0x72, 0x00];
        assert_eq!(smb_dialect(&smb1), Some("SMB1"));
        assert_eq!(smb_dialect(&[0x00, 0x01, 0x02]), None);
        assert_eq!(smb_dialect(&[0, 0, 0, 0, 0x42, 0, 0, 0]), None);
    }

    #[test]
    fn ssh_banner_parsing() {
        let (p, v) = parse_ssh_banner("SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10").unwrap();
        assert_eq!(p, "OpenSSH");
        assert_eq!(v, "7.2p2");
        let (p2, v2) = parse_ssh_banner("SSH-1.99-Cisco-1.25").unwrap();
        assert_eq!(p2, "Cisco-1.25");
        assert_eq!(v2, "");
        assert!(parse_ssh_banner("HTTP/1.1 200 OK").is_none());
        assert!(parse_ssh_banner("").is_none());
    }

    #[test]
    fn version_ranges_cover_known_advisories() {
        // CVE-2018-15473 (enumeracion de usuarios): OpenSSH 7.0 - 7.6
        assert!(version_in_range("7.2p2", "7.0", "7.6"));
        assert!(
            version_in_range("7.6p1", "7.0", "7.6"),
            "el parche no cambia el rango"
        );
        assert!(!version_in_range("7.7", "7.0", "7.6"));
        assert!(!version_in_range("6.9", "7.0", "7.6"));
        // CVE-2023-38408: OpenSSH 8.0 - 9.3
        assert!(version_in_range("9.3p1", "8.0", "9.3"));
        assert!(version_in_range("8.0", "8.0", "9.3"));
        assert!(!version_in_range("9.4", "8.0", "9.3"));
        // Bordes invalidos
        assert!(!version_in_range("", "7.0", "7.6"));
        assert!(!version_in_range("OpenSSH", "7.0", "7.6"));
    }

    #[test]
    fn version_key_takes_major_and_minor() {
        assert_eq!(version_key("7.2p2"), [7, 2]);
        assert_eq!(version_key("9.3"), [9, 3]);
        assert_eq!(version_key("10.14.1"), [10, 14]);
        assert_eq!(version_key("v1"), [1, 0]);
    }
}
