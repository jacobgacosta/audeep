# AuDeep — Arquitectura y Diseño (Rust) · v0.2

> Offline-first, portable USB y plug&play Raspberry Pi. Un binario, sin servicios externos.
> Origen: `knowledge/dispositivo_auditor.md` → migrado a `docs/architecture.md` y versionado en `jacobgacosta/audeep`.

## Principio de diseño

Cada afirmación del reporte tiene que poder sostenerse:

1. **¿Está vivo?** No se adivina: se prueba en capa 2 (ARP) y, si no, se acepta un RST de TCP como prueba de vida. El `ping` solo cuenta si la salida trae `TTL=`, porque es lo único que no se traduce.
2. **¿Es vulnerable?** Un puerto abierto no es una vulnerabilidad. Cuando se puede confirmar sin exploits, se confirma (SMBv1 negociado, versión de OpenSSH contra rangos); cuando no, se dice `probable` o `sospecha` y se muestra la evidencia.
3. **¿Qué cambió?** Cada escaneo se compara con el anterior; las anomalías de capa 2 (MAC repetida, MAC del gateway cambiada) son alertas, no adornos.

## Stack

| Capa | Crate | Uso |
|------|-------|-----|
| Hardware | `sysinfo 0.30` + `Components` | OS, kernel, uptime, `load_avg`, CPU (marca/vendor/núcleos/freq), RAM, discos, MACs, temperaturas |
| Interfaces | `if-addrs 0.13` | IPs por interfaz y **máscara real** para calcular el prefijo (no se asume /24) |
| Red | `tokio` + `dns-lookup` + `mdns-sd` | Barrido ARP-first por UDP, TCP de 3 estados, reverse DNS 500 ms, mDNS (9 servicios) y SSDP M-SEARCH |
| Sondas | propio (`probe.rs`) | Negociación SMB1 de 73 bytes y parseo de banners SSH |
| Vulnerabilidades | `rusqlite 0.31 bundled` + `serde_json` | Reglas curadas en JSON (con rangos de versión) + CVEs de NVD en SQLite, cacheadas con `OnceLock` |
| Riesgo | propio (`risk.rs`) | Score 0-100 por severidad, certeza y exposición de servicios |
| Historial | `rusqlite` | `scans` + `devices`, diff y anomalías, poda a los últimos 200 escaneos |
| Reporte | `chrono` | JSON + HTML crema offline (Canvas 2D, sin CDN) con riesgo, evidencia, eventos y export CSV/JSONL |
| Serve | `tokio::net::TcpListener` | Loopback por defecto, caché con TTL, `ETag`/`304`, token opcional, `/scan` |
| CLI | `clap 4 derive` | `--no-scan`, `--json/--html`, `--history/--no-history`, `--config`, `--serve*` |
| Build | `zig` + `cargo-zigbuild` | `aarch64` / `armv7` / `x86_64-musl` estáticos de ~7 MB |

## Flujo

```
main.rs
 ├─ config::AuditConfig::load()          (audeep.json o --config)
 ├─ scanner::set_ports(cfg.ports)
 ├─ hardware::collect_hardware_info()    (sysinfo + if-addrs)
 ├─ network::discover_hosts(t, n)        ARP sweep → candidatos → puertos
 │    └─ vuln::check_host()              reglas + confianza + evidencia
 ├─ network::enrich_with_arp()           MAC/vendor (+fuente) y merge de silenciosos
 ├─ network::enrich_with_mdns_ssdp()     nombres reales y deducción de fabricante
 ├─ history::History::diff_and_record()  eventos: nuevo/desaparecido/puerto nuevo + anomalías L2
 ├─ risk::score_host()                   score, nivel y motivos por host
 └─ report::AuditReport → JSON + HTML → serve (opcional)
```

## Módulos

### `hardware.rs`
`System::new_all()`, `Disks::new_with_refreshed_list()`, `Networks`, `Components`, `System::load_average()`. Las IPs de cada interfaz se completan con `if-addrs` (sysinfo solo da MAC) y si el volumen no tiene nombre se usa el punto de montaje.

### `arp.rs`
`parse_arp_table()` acepta la salida de `arp -a` (Windows, con encabezados y campo *Type* en cualquier idioma) y `/proc/net/arp` (Linux): exige IPv4 en la primera columna, busca la MAC en las siguientes, valida 6 octetos hexadecimales y descarta multicast/broadcast/cero. `is_locally_administered()` detecta el bit `0x02`.

### `network.rs`
- `local_net()`: IP + prefijo real desde la máscara (`netmask_to_prefix` valida contigüidad).
- `arp_sweep()`: dos rondas de UDP a todos los hosts del alcance para forzar ARP; después lee la tabla. En redes grandes el alcance se limita al `/24` propio.
- `discover_hosts()`: candidatos = respondieron ARP; si la tabla no dio nada, cae al barrido TCP+ping acotado.
- `is_host_alive()`: puerto abierto o **RST** (`Probe::Refused`); si no, `ping` con `TTL=`.
- `lookup_vendor_guess()`: curado → bit de MAC local → registro de 40k prefijos, siempre devolviendo la fuente.
- `enrich_with_mdns_ssdp()`: nombres mDNS/SSDP, deducción por tokens (`contains_token`) y confirmación HTTP opcional.

### `scanner.rs`
`Probe { Open, Refused, Filtered }`, `probe_port`, `should_grab_banner` (solo servicios que saludan primero: 80/443/3389 no gastan 800 ms), `active_ports`/`set_ports` para la config y enriquecimiento del 445 con el dialecto SMB negociado.

### `probe.rs`
`smb1_negotiate_request()` (NetBIOS 4 + SMB 32 + WordCount + ByteCount + 3 dialectos = 73 bytes), `smb_dialect()` (`0xFF` SMB1 / `0xFE` SMB2-3), `parse_ssh_banner()`, `version_key()` y `version_in_range()`.

### `vuln.rs`
`VulnEntry` con `match_ports`, `match_banner_contains`, `match_versions` y `confidence`. `load_db()` mezcla el JSON curado (fuente de verdad, incluye rangos) con lo que aporte la SQLite de NVD, sin repetir CVEs, y cachea con `OnceLock`. `check_port()` combina los criterios y produce `Finding` con `confidence` y `evidence`.

### `risk.rs`
`score_host()`: peso por severidad ajustado por certeza (una crítica confirmada pesa más que una sospecha) + exposición de servicios sensibles (RDP, Telnet, VNC, SMB, bases de datos). Niveles: `sin riesgo`, `bajo`, `medio`, `alto`, `critico`.

### `history.rs`
Tablas `scans` y `devices`. `diff_and_record()` guarda el escaneo y devuelve eventos: `nuevo`, `desaparecido`, `puerto_nuevo`, `mac_duplicada` (misma MAC en varias IP) y `gateway_cambio` (heurística: la IP más baja, casi siempre `.1`). Poda a los últimos 200 escaneos.

### `report.rs`
JSON pretty con todo el detalle y HTML offline: tarjetas de estadísticas (incluye hosts críticos), tabla ordenada por riesgo con score y motivos, hallazgos con severidad + confianza + evidencia, panel de cambios desde el último escaneo, discos e interfaces con IPs, gráficos Canvas y export **CSV** y **JSONL** generado en el navegador (funciona también desde `file://`).

### `serve.rs`
`TcpListener`. Rutas `/` (HTML), `/json`, `/health`, `/scan` (fuerza), `/docs`, `/docs/conceptos`. Caché con TTL configurable y regeneración en segundo plano (sirve lo viejo mientras escanea), `ETag` con `304`, `X-Content-Type-Options`, `Referrer-Policy`, CORS `*` para el frontend de 5111 y token opcional por query o cabecera.

### `config.rs`
`audeep.json` con `probe_timeout_ms`, `concurrency`, `mdns_timeout_ms`, `ports` y `exclude`; todos opcionales, normalizados y validados.

## Portabilidad

- **USB**: `x86_64-unknown-linux-musl` estático (sin `glibc`).
- **Pi**: `aarch64`/`armv7` con `scripts/build_rpi.ps1` (zig), `deploy/systemd/audeep.service`, `deploy/usb/` y `deploy/ap/` (`AuDeep-Auditor`, `192.168.4.1`, hostapd + dnsmasq).
- **Docker**: imagen distroless; sin `ping`/`arp` el descubrimiento se apoya solo en TCP, así que conviene `--network host`.

## Frontend independiente (`../audeep-web`)

Vite + React + Chart.js consume `http://127.0.0.1:8766/json` cada 5 s. Los campos nuevos (`vendor_source`, `confidence`, `evidence`, `events`, `critical_hosts`) son aditivos: el frontend sigue funcionando y puede adoptarlos cuando quiera.

## Roadmap

- [x] Veredicto de host por ARP/TTL/RST
- [x] Parser ARP multi-formato + descubrimiento ARP-first
- [x] Subred real por máscara e IPs de interfaz
- [x] Vendor con fuente y sin falsos positivos
- [x] Confirmación de SMBv1 y rangos de versión SSH
- [x] Confianza y evidencia por hallazgo
- [x] Score de riesgo por host y orden por riesgo
- [x] Historial con diff y anomalías de capa 2
- [x] `serve` con caché, token, ETag y bind seguro por defecto
- [x] `audeep.json` y caché de la base de CVEs
- [x] Reporte v2 con evidencia y export CSV/JSONL
- [x] CI (fmt + clippy + tests en Linux y Windows)
- [ ] Probar RDP (X.224/NLA) para confirmar BlueKeep
- [ ] Notificaciones (webhook/Telegram) cuando aparezca un dispositivo o cambie el gateway
- [ ] Actualización automática del registro OUI desde IEEE
- [ ] Empaquetado `.deb`/`.rpm` y release con los binarios de las tres arquitecturas
