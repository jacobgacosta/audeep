# AuDeep — Auditor de Hardware y Red (Rust)

Herramienta offline, portable (USB) y plug&play (Raspberry Pi) para inventario de hardware, descubrimiento de red, escaneo de puertos y detección básica de vulnerabilidades. Un solo binario estático, sin dependencias.

## Características
- **Hardware local** (`hardware.rs`): OS, CPU (marca/vendor/cores/freq), RAM, discos, interfaces (MAC) via `sysinfo 0.30`.
- **Descubrimiento** (`network.rs`): subnet /24 via UDP trick, 254 hosts con 64 tareas paralelas, `is_host_alive` por TCP 80/445/22/53 + `ping` binario fallback, ARP `arp -a` / `/proc/net/arp` + OUI `assets/oui.json` (~90 entradas).
- **Escáner** (`scanner.rs`): `tokio` async, 21 puertos comunes, banner grab 800ms, `COMMON_PORTS`.
- **Vuln** (`vuln.rs`): DB offline `assets/vuln_db.json` (7 CVEs: EternalBlue, BlueKeep, Heartbleed...), correlación por puerto/banners.
- **Reporte** (`report.rs`): JSON + HTML dark autocontenido (sin CDN).

## Uso rápido (Windows)
```pwsh
$env:PATH="C:\Users\jacob\AppData\Local\Temp\zig-x86_64-windows-0.16.0;"+$env:PATH
cargo zigbuild --target x86_64-pc-windows-gnu
.\target\x86_64-pc-windows-gnu\debug\audeep.exe
# o sin escanear: .\audeep.exe --no-scan
# salida custom: .\audeep.exe --json=.\out.json --html=.\out.html
```

## Opciones CLI
- `--no-scan` — solo hardware
- `--json=PATH` — JSON destino
- `--html=PATH` — HTML destino
- por defecto guarda `audeep_reporte.json` + `audeep_reporte.html` en cwd

## Raspberry Pi (ver `deploy/README.md`)
```bash
# Build cruzado con zig (desde Windows):
powershell -File scripts/build_rpi.ps1  # genera aarch64/armv7/musl
scp target/aarch64-unknown-linux-gnu/release/audeep pi@pi:/tmp/
ssh pi@pi 'sudo mv /tmp/audeep /usr/local/bin/ && sudo systemctl enable --now audeep'
```

## Estructura
```
audeep/
  assets/oui.json, vuln_db.json  # embebidos con include_str!
  src/hardware.rs, scanner.rs, network.rs, vuln.rs, report.rs, main.rs
  deploy/systemd/audeep.service, audeep-usb@.service
  deploy/usb/99-audeep-usb.rules, audeep-usb.sh
  scripts/build_rpi.ps1, build_rpi.sh
```

## Próximos pasos
- OUI completa IEEE (28000 entradas) comprimida
- CVE feed NVD offline con SQLite
- mDNS/SSDP para naming
- Modo AP Wi-Fi en Pi (portal cautivo)
