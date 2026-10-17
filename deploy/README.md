# AuDeep — Despliegue

Guía para llevar AuDeep a un pendrive, una Raspberry Pi o Docker. Para el uso normal en tu PC alcanza con `cargo build` y ejecutar el binario.

## USB portable (sin instalación)

1. Compilar estático: `cargo zigbuild --target x86_64-unknown-linux-musl --release` (o `--target x86_64-pc-windows-gnu` para Windows).
2. Copiar el binario (`target/.../release/audeep`) a un pendrive. Los assets (OUI y base de CVEs) van **embebidos**: no hace falta copiar `assets/`.
3. En el equipo destino: `./audeep --json=./audeep_reporte.json --html=./audeep_reporte.html --history=./audeep_history.db`
4. Abrir `audeep_reporte.html` en el navegador (funciona offline, sin servidor).

Atajos útiles: `--no-scan` (solo hardware) y `--serve` (lo levanta como página web).

## Raspberry Pi (plug & play)

### Instalación rápida (Pi OS 64-bit)

```bash
# En tu PC (con zig y cargo-zigbuild instalados):
powershell -File scripts/build_rpi.ps1     # genera el binario aarch64

# Copiar a la Pi:
scp target/aarch64-unknown-linux-gnu/release/audeep pi@192.168.1.50:/tmp/
ssh pi@192.168.1.50
sudo mv /tmp/audeep /usr/local/bin/audeep
sudo chmod +x /usr/local/bin/audeep
sudo mkdir -p /var/lib/audeep              # acá quedan reportes e historial

# Servicios:
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

- Cuando hay red (`network-online.target`), `audeep.service` ejecuta
  `/usr/local/bin/audeep --json=/var/lib/audeep/audeep_reporte.json --html=/var/lib/audeep/audeep_reporte.html --history=/var/lib/audeep/audeep_history.db`
  y parpadea el LED 3 veces.
- **El historial es lo que hace útil dejarlo corriendo**: cada arranque compara contra el escaneo anterior y te avisa de equipos nuevos, desaparecidos y puertos que se abrieron. Si no lo querés, agregá `--no-history`.
- Al insertar un USB, `99-audeep-usb.rules` dispara `audeep-usb@.service` → `audeep-usb.sh` monta en `/mnt/audeep_usb`, copia el reporte a `AuDeep_<timestamp>/` + `AuDeep_reporte.html` en la raíz, hace `sync`, parpadea 6 veces y desmonta.
- El usuario retira el USB con el reporte listo, sin monitor ni teclado.

### Ajustes por equipo (`audeep.json`)

Dejá un `audeep.json` en el directorio de trabajo (o pasá `--config /etc/audeep.json`) para adaptar el escaneo sin recompilar:

```json
{ "probe_timeout_ms": 400, "ports": [21, 22, 80, 443, 445, 3389], "exclude": ["192.168.1.50"] }
```

Sirve, por ejemplo, para no escanear la impresora que se cae, o para mirar puertos extra en una red concreta. Ver `audeep.example.json`.

### Modo servidor en la Pi

Por defecto `--serve` escucha **solo en loopback** (nadie de la red lo ve). Para verlo desde otro equipo hay que pedirlo a propósito y conviene protegerlo:

```bash
audeep --serve 0.0.0.0:8766 --serve-token MI_CLAVE   # http://<ip-de-la-pi>:8766/?token=MI_CLAVE
```

Rutas: `/` (reporte), `/json`, `/health`, `/scan` (fuerza reescaneo), `/docs`, `/docs/guia` y `/docs/conceptos`.

### Cross-compilación: notas

- `zig cc` evita instalar el toolchain ARM: `cargo zigbuild --target aarch64-unknown-linux-gnu` usa zig como linker.
- Para Pi Zero (armv6) usá `arm-unknown-linux-gnueabihf`.
- Ver `scripts/build_rpi.ps1` para todos los targets.

### Permisos de red

- **No requiere `CAP_NET_RAW`**: usa TCP connect (tres estados), el `ping` del sistema, el barrido ARP por UDP y la lectura de `arp -a` / `/proc/net/arp`.
- Para un futuro ARP con raw sockets: `sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/audeep`.

### Reportes

- JSON: `/var/lib/audeep/audeep_reporte.json` (para integración)
- HTML: `/var/lib/audeep/audeep_reporte.html` (autocontenido, **crema**, sin dependencias ni CDN)
- Historial: `/var/lib/audeep/audeep_history.db` (SQLite; se poda solo a los últimos 200 escaneos)

## Docker

```bash
docker build -t audeep:latest .
docker run --rm --network host -v "$PWD:/out" audeep:latest --json=/out/audeep_reporte.json --html=/out/audeep_reporte.html
docker run --rm -p 8766:8766 audeep:latest --serve 0.0.0.0:8766
```

La imagen final es `distroless` y **no** trae `ping` ni `arp`: el descubrimiento se apoya solo en TCP y en la tabla ARP del kernel (dentro de un contenedor suele estar vacía), así que para auditar una red de verdad se recomienda `--network host`.
