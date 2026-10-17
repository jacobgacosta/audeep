# Changelog

Todos los cambios relevantes de AuDeep.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado [SemVer](https://semver.org/lang/es/).

## [0.2.0]

Versión enfocada en **no mentir**: que cada afirmación del reporte esté sostenida por una prueba, y que el escaneo avise qué cambió en la red.

### Agregado

- **Descubrimiento ARP-first** (`network::arp_sweep`): barrido por UDP que fuerza la resolución ARP de toda la red y después lee la tabla. Aparecen también los equipos que no exponen ningún puerto.
- **Confirmación real de SMBv1** (`src/probe.rs`): se negocia el protocolo en el 445 (pedido de 73 bytes) y se mira qué dialecto acepta el equipo. Solo si acepta SMB1 se marca EternalBlue.
- **Rangos de versión de SSH**: del banner se extrae producto y versión y se compara contra los rangos publicados (6.0-7.1, 7.0-7.6, 8.0-9.3), en vez de buscar substrings.
- **Confianza y evidencia por hallazgo**: `confirmado` / `probable` / `sospecha`, más el dato que sostiene el aviso.
- **Score de riesgo por equipo** (`src/risk.rs`): 0-100 combinando severidad, certeza y exposición de servicios; el reporte se ordena por riesgo.
- **Historial SQLite con diff y anomalías de capa 2** (`src/history.rs`): equipos nuevos, desaparecidos, puertos que se abrieron, la **misma MAC en varias IP** (ARP spoofing o virtualización) y el **cambio de MAC del router** (posible intermediario).
- **`audeep.json`** (`src/config.rs`): timeouts, concurrencia, puertos y exclusiones, con validación y normalización.
- **`serve`**: `/scan` para forzar un escaneo, `--serve-interval`, `--serve-token`, `ETag` con `304`, `X-Content-Type-Options` y `Referrer-Policy`.
- **Reporte v2**: evidencia visible, panel de cambios desde el escaneo anterior, IPs de cada interfaz, contador de equipos críticos y export **CSV** y **JSONL** desde el navegador.
- **Módulos nuevos**: `arp.rs`, `probe.rs`, `risk.rs`, `history.rs`, `config.rs`.
- **CI** con GitHub Actions: `cargo fmt --check`, `cargo clippy -D warnings` y `cargo test` en Ubuntu y Windows.
- **Licencia MIT** y documentación al día (guía simple, referencia técnica y arquitectura).

### Cambiado

- El veredicto de "equipo vivo" ya no depende de textos del `ping`: se apoya en ARP, en un rechazo de TCP (RST) y, como respaldo, en el `TTL=`.
- La base de vulnerabilidades se carga **una sola vez** (`OnceLock`) y mezcla lo curado (con rangos de versión) con los CVEs de la base SQLite, sin repetir.
- La subred se calcula con la **máscara real** de la interfaz (`if-addrs`), no asumiendo `/24`; en redes grandes el barrido se acota.
- El fabricante se informa **con su fuente** (`oui`, `oui-local`, `hostname`, `mdns`, `ssdp`, `banner`, `puerto`, `http`).
- `--serve` escucha **solo en loopback** por defecto y refresca el reporte cada **60 s** (antes `0.0.0.0` y 12 s).
- El banner se lee solo donde el servicio saluda primero (ya no se pierden 800 ms por equipo en 80/443).
- Versión del paquete a `0.2.0`.

### Corregido

- Falsos positivos de **EternalBlue**: se marcaba por tener el 445 abierto.
- Falsos positivos de **SSH**: la coincidencia por substrings fallaba con versiones como `7.2p2`.
- **Equipos fantasma**: la heurística del ping (textos en inglés) daba por vivos equipos inexistentes (69 donde había 11).
- **Precedencia de operadores** al parsear `arp -a`, que además metía MACs basura y multicast en el mapa.
- **Falsos positivos de marca**: `contains("mi ")` marcaba Xiaomi a un equipo llamado `miguel-pc` (ahora se comparan tokens completos).
- `load_db()` escribía un SQLite temporal **por equipo**.
- Interfases de red sin IP en el reporte y discos sin nombre en Windows.
- Los **19 warnings** de clippy; hoy `cargo clippy -D warnings` queda en cero.

### Seguridad

- El servidor ya no publica el inventario de la red sin querer (loopback por defecto) y acepta token por query o cabecera.
- Cabeceras de seguridad en todas las respuestas y `304` para no reenviar el mismo reporte.

## [0.1.0]

Versión inicial: inventario de hardware (`sysinfo`), descubrimiento de red (TCP + ping + ARP), escaneo de 21 puertos con banner, base de 7 CVEs curados en SQLite (`assets/cve.db`) ampliable con `xtask fetch-nvd`, reporte JSON + HTML crema offline, servidor propio en el 8766, despliegue en Raspberry Pi/USB y frontend React independiente (`audeep-web`).
