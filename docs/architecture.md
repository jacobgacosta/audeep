# AuDeep — Arquitectura y Diseño (Rust) · v0.1.0

> **Origen:** `knowledge/dispositivo_auditor.md` (diseño inicial) → migrado a `audeep/docs/architecture.md` versionado para `jacobgacosta/audeep`. Offline-first, portable USB y plug&play Raspberry Pi.

## Stack actual (verificado `9d67bfd` + `b903a5c`)

| Capa | Crate | Uso |
|------|-------|-----|
| Hardware | `sysinfo 0.30` + `Components` | OS, kernel, uptime, `load_avg 1/5/15`, CPU `brand/vendor/cores/freq`, RAM `total/used/available`, `Disks`, `Networks` MAC, sensores temp |
| Red | `tokio` 64 tasks + `dns-lookup` 2.1 + `mdns-sd 0.11` | Subnet `/24` UDP trick `8.8.8.8:80`, `is_host_alive` TCP 80/445/22/53 + `ping -n/-c` TTL, `arp -a`/`/proc/net/arp` + OUI 40k `assets/oui_full.json` + `locally-administered` bit `0x02`, reverse DNS 500ms, mDNS `browse _http._tcp` + SSDP M-SEARCH `239.255.255.250:1900` |
| Scanner | `tokio` | `COMMON_PORTS` 21 puertos, `scan_port` con banner 800ms, `scan_common_ports` concurrente |
| Vuln | `rusqlite 0.31 bundled` + `serde_json` | `assets/cve.db` SQLite 7 curados (EternalBlue 445, BlueKeep 3389, Heartbleed) + NVD fetch 90d via `xtask fetch-nvd --limit 30 --merge` (`reqwest rustls`), `include_bytes!` offline |
| Reporte | `chrono` | `AuditReport` JSON pretty + HTML crema hack offline `src/report.rs:1` Canvas 2D sin CDN (`file://` + `http://127.0.0.1:8766/`) |
| Serve | `tokio::net::TcpListener` | `0.0.0.0:8766` (evita Koupper 8080) `GET /` `GET /json` `GET /health` `GET /docs`, `Access-Control-Allow-Origin: *`, cache 12s + loading 0.01s non-blocking |
| CLI | `clap 4 derive` | `--no-scan` `--json/--html` `--serve [ADDR]` default `8766` |
| Build | `zig 0.16` `cargo-zigbuild` | `aarch64`/`armv7`/`musl` 7MB estáticos, `xtask` Rust puro |

## Diagrama

```
[Hardware sysinfo] → [Network tokio 64 + arp + OUI 40k + mdns/ssdp] → [Scanner 21 ports] → [Vuln rusqlite cve.db] → [Report crema] → [Serve 8766] → [Web 5111 React Chart.js]
         ↓                                    ↓
   Disks/IFaces/Sensors              mDNS _http._tcp + SSDP 239.255.255.250
```

Flujo `main.rs`: `collect_hardware_info()` → `discover_hosts(320,64)` → `enrich_with_arp` → `enrich_with_mdns_ssdp(800ms)` → `scan_common_ports` → `check_host(cve.db)` → `AuditReport::new → to_html/to_json` → `serve 8766` → `5173 fetch /json 5s`.

## Módulos

### `hardware.rs`
`System::new_all()` + `Disks::new_with_refreshed_list()` + `Networks` + `Components` + `System::load_average()`. Convierte bytes a GB `1024³`. Sin `raw-cpuid` (se usa `sysinfo` vendor).

### `network.rs`
- `get_local_ipv4()` UDP trick, `local_subnet_cidr()` `/24`, `hosts_in_subnet()`
- `is_host_alive` + `ping_host` TTL check, `try_resolve_hostname` `dns_lookup` 500ms `spawn_blocking`
- `discover_hosts` 64 concurrency, `enrich_with_arp` merge + `enrich_with_mdns_ssdp` 800ms
- `discover_mdns_map` `mdns_sd::ServiceDaemon` browse 9 services, `discover_ssdp_map` UDP M-SEARCH

### `vuln.rs`
`VulnEntry` `match_banner_contains`/`match_ports`, `load_db()` jerárquico `cve.db` junto a binario → `cwd` → `include_bytes!` → fallback `vuln_db.json`, `query_sqlite` para NVD.

### `report.rs`
Crema `#fdfbf7` hack `›_ AuDeep :: AUDIT`, stats 4, charts Canvas 2D (vendors 6, sev dona 220x220, ports 8), tabla 9 cols filtrable `data-ip/vendor/sev`, `file://` offline.

### `serve.rs`
`TcpListener` `0.0.0.0:8766`, cache `Arc<Mutex<Option<(Instant,json,html)>>>` 12s + `scanning` flag, `GET /` loading 1045 bytes `meta refresh 2s` si no hay cache, `GET /json` 202 scanning else 200, CORS `*`.

## Portabilidad

- **USB musl** `x86_64-unknown-linux-musl` estático sin `glibc`
- **Pi** `aarch64`/`armv7` via `scripts/build_rpi.ps1` `zig`, `deploy/systemd/audeep.service` + `audeep-usb@.service` + `99-audeep-usb.rules` + `deploy/ap/hostapd.conf` `AuDeep-Auditor` `192.168.4.1` `dnsmasq`

## Frontend independiente `audeep-web` (Vite 8 + React 19 + TS 6 + Chart.js 4 + Tailwind 3)

- `src/types.ts` espejo Rust, `src/api/audeep.ts` `BASE 8766` `fetchHealth/fetchAudit` con `202` handling, `src/App.tsx` dashboard crema + `src/components/Docs.tsx` este doc, `vite.config.ts` `5111`
- `npm run dev` → `http://127.0.0.1:5111/` fetch `http://127.0.0.1:8766/json` polling 5s

## Hoja de ruta

- [x] OUI 40k + `OnceLock` + locally-administered
- [x] `cve.db` SQLite + `xtask fetch-nvd` 90d
- [x] `mDNS/SSDP` + `serve` + `clap` + `xtask` Rust
- [x] Reporte crema hack + dona fix + `5111`/`8766`
- [ ] `cargo test` cobertura + `clippy`
- [ ] `docs` in-site ya en `5111` tab Docs + `8766/docs` (este archivo)
