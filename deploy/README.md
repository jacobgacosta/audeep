# AuDeep - Despliegue

## USB portable (sin instalación)
1. Compilar estático: `cargo zigbuild --target x86_64-unknown-linux-musl --release` (o `x86_64-pc-windows-gnu` para Windows)
2. Copiar `target/.../release/audeep` + `assets/` a un pendrive.
3. En el host objetivo ejecutar `./audeep --html=./audeep_reporte.html` (no requiere deps, binario estático).
4. Abrir `audeep_reporte.html` en el navegador.

## Raspberry Pi (plug & play)
### Instalación rápida (Pi OS 64-bit)
```bash
# En tu PC (Windows con zig):
powershell -File scripts/build_rpi.ps1   # genera aarch64 binario

# Copiar a la Pi:
scp target/aarch64-unknown-linux-gnu/release/audeep pi@192.168.1.50:/tmp/
scp -r assets pi@192.168.1.50:/tmp/assets
ssh pi@192.168.1.50
sudo mv /tmp/audeep /usr/local/bin/audeep
sudo chmod +x /usr/local/bin/audeep
sudo mkdir -p /var/lib/audeep
sudo cp -r /tmp/assets /var/lib/audeep/  # opcional si embebes con include_str ya no necesario

# Servicios
sudo cp deploy/systemd/audeep.service /etc/systemd/system/
sudo cp deploy/systemd/audeep-usb@.service /etc/systemd/system/
sudo cp deploy/usb/audeep-usb.sh /usr/local/bin/ && sudo chmod +x /usr/local/bin/audeep-usb.sh
sudo cp deploy/usb/99-audeep-usb.rules /etc/udev/rules.d/
sudo udevadm control --reload
sudo systemctl daemon-reload
sudo systemctl enable --now audeep
journalctl -u audeep -f
```

### Comportamiento
- Al arrancar y tener red (`network-online.target`), `audeep.service` ejecuta `/usr/local/bin/audeep --json=/var/lib/audeep/audeep_reporte.json --html=/var/lib/audeep/audeep_reporte.html` y parpadea LED 3 veces.
- Al insertar USB, `99-audeep-usb.rules` dispara `audeep-usb@.service` → `audeep-usb.sh` monta en `/mnt/audeep_usb`, copia reporte a `AuDeep_<timestamp>/` + `AuDeep_reporte.html` en raíz, `sync`, parpadea 3 largos + 5 rápidos, desmonta.
- El usuario retira el USB con el reporte listo sin necesidad de monitor.

### Cross-compilación notas
- `zig cc` evita instalar toolchain ARM: `cargo zigbuild --target aarch64-unknown-linux-gnu` usa zig como linker.
- Para Pi Zero (armv6) usa `arm-unknown-linux-gnueabihf`.
- Ver `scripts/build_rpi.ps1` para todos los targets.

### Permisos de red
- No requiere `CAP_NET_RAW` porque usa TCP connect + `ping` binario + lectura `arp -a` / `/proc/net/arp`.
- Para `libpnet` raw ARP futuro: `sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/audeep`.

### Reportes
- JSON: `/var/lib/audeep/audeep_reporte.json` (para integración)
- HTML: `/var/lib/audeep/audeep_reporte.html` (autocontenido, dark, sin deps)
