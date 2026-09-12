# AuDeep — Auditor de Hardware y Red (Rust) · Backend

Herramienta offline, portable (USB) y plug&play (Raspberry Pi) para inventario de hardware, descubrimiento de red, escaneo de puertos y detección de vulnerabilidades. Un solo binario estático, sin dependencias. **Proyecto independiente y limpio** (ver `audeep-web` para frontend).

## Características
- **Hardware** `src/hardware.rs:1` OS/CPU/RAM/Discos/IFaces/Sensores (`sysinfo 0.30` + `Components` + `load_avg`)
- **Descubrimiento** `src/network.rs:1` subnet `/24` UDP trick, 254 hosts 64 tasks, `is_host_alive` TCP 80/445/22/53 + `ping` TTL, `arp -a` + OUI 40k `assets/oui_full.json:1` + `locally-administered`, reverse DNS `dns-lookup` + `mdns-sd` + `SSDP` M-SEARCH
- **Escáner** `src/scanner.rs:1` `tokio` async 21 `COMMON_PORTS` banner 800ms
- **Vuln** `src/vuln.rs:1` SQLite offline `assets/cve.db:1` (7 curados + NVD fetch via `xtask` `rusqlite bundled`) + `xtask fetch-nvd` 90d window
- **Reporte** `src/report.rs:1` JSON + HTML crema hack minimalista offline (Canvas 2D, sin CDN, `file://` + `http://127.0.0.1:8766/`)
- **Serve** `src/serve.rs:1` `TcpListener` `0.0.0.0:8766` (evita Koupper 8080) `GET /` `GET /json` `GET /health` con `Access-Control-Allow-Origin: *` + cache 12s + loading non-blocking
- **CLI** `src/main.rs:1` `clap 4 derive` `--no-scan` `--json` `--html` `--serve [ADDR]` (default `8766`)

## Uso rápido (Windows)
```pwsh
$env:PATH="C:\Users\jacob\AppData\Local\Temp\zig-x86_64-windows-0.16.0;"+$env:PATH
cargo zigbuild --target x86_64-pc-windows-gnu
.\target\x86_64-pc-windows-gnu\debug\audeep.exe --help
.\target\x86_64-pc-windows-gnu\debug\audeep.exe
# 14 hosts 3 vulns -> audeep_reporte.html (crema 35KB) + audeep_reporte.json
start audeep_reporte.html
# o serve live:
.\target\x86_64-pc-windows-gnu\debug\audeep.exe --serve
# abre http://127.0.0.1:8766/ (Escaneando… 0.01s -> mamón 10s bg)
```

## CLI
- `--no-scan` solo hardware
- `--json <PATH>` `--html <PATH>` salida custom
- `--serve [ADDR]` default `0.0.0.0:8766` (usa `8766` para no pisar Koupper 8080)
- `--help` `--version` via `clap`

## Frontend independiente
Ver `../audeep-web/README.md` (Vite + React 19 + TS + Chart.js). Consume `http://127.0.0.1:8766/json` polling 5s.
```pwsh
cd ../audeep-web; npm install; npm run dev # http://localhost:5173
```

## Raspberry Pi / USB (ver `deploy/`)
```bash
powershell -File scripts/build_rpi.ps1 # aarch64/armv7/musl 7.2-7.6MB
scp target/aarch64-unknown-linux-gnu/release/audeep pi@pi:/tmp/
ssh pi@pi 'sudo mv /tmp/audeep /usr/local/bin/ && sudo systemctl enable --now audeep'
# AP: sudo audeep-ap on # AuDeep-Auditor 192.168.4.1 http://192.168.4.1
```

## Estructura limpia
```
audeep/
  Cargo.toml (workspace + xtask)
  src/{main,hardware,network,scanner,vuln,report,serve}.rs
  assets/{oui.json,oui_full.json(40k),vuln_db.json,cve.db}
  xtask/src/main.rs (build-cve / fetch-nvd --limit 30 --merge)
  .cargo/config.toml (alias xtask)
  deploy/{systemd,usb,ap}  scripts/build_rpi.ps1
```
Best practices: `cargo fmt` + `clippy`, `serde` derive, `tokio` full, `sysinfo` 0.30, `clap` derive, `rusqlite bundled` + `mdns-sd`, `xtask` Rust puro (sin Python), `include_str!`/`include_bytes!` offline.

## Docs
- `docs/architecture.md` (versionado, migrado de `knowledge/dispositivo_auditor.md`) — arquitectura completa + diagrama + stack
- In-site: `http://127.0.0.1:5111/` tab **Docs** y `http://127.0.0.1:8766/docs` (serve)
- `deploy/ap/README.md` modo AP
- `xtask fetch-nvd --help` NVD API 2.0 90d
