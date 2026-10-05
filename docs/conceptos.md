# AuDeep — Conceptos: qué es cada cosa y para qué sirve

> Referencia técnica. Cada concepto: definición, para qué sirve y ejemplo real de tus equipos.
> Verificado en: Jetson Orin Nano `192.168.1.21` (Ubuntu 22.04, JetPack R36.5, CUDA 12.6) y red `192.168.1.0/24`.

---

## 1. PATH

**Qué es:** variable de entorno con la lista ordenada de directorios donde el shell busca un comando cuando lo escribes sin ruta.

**Para qué sirve:** evita escribir `/usr/local/cuda-12.6/bin/nvcc` cada vez; basta `nvcc`. El shell prueba cada directorio en orden y ejecuta la primera coincidencia (`type -a` / `which -a` muestran cuál ganó).

**Ejemplo real (tu Jetson):**
```
$ echo $PATH | tr ':' '\n'
/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin ...
```
`nvcc` vivía en `/usr/local/cuda-12.6/bin/nvcc`, directorio que NO estaba en esa lista → `command not found` aunque el binario existía. Fix aplicado: exportar ese directorio en `~/.profile`.

---

## 2. LD_LIBRARY_PATH

**Qué es:** el gemelo del PATH pero para **librerías compartidas** (`.so`): `libcudnn.so.9`, `libcublas.so`, etc.

**Para qué sirve:** cuando un programa arranca, el linker (`ld.so`) busca ahí las librerías que necesita. Sin esto, compila bien pero al correr falla con `error while loading shared libraries`.

**Ejemplo real:** en tu Jetson vale `/usr/local/cuda-12.6/lib64`, donde están `libcudnn_*` 9.3.0.

---

## 3. Archivos de arranque del shell (.bashrc, .profile) y el guard `case $-`

**Qué es:** scripts que bash lee al arrancar para definir el entorno. `~/.profile` lo leen los **login shells** (siempre); `~/.bashrc` los interactivos. Tu `.bashrc` empieza con:
```bash
case $- in
    *i*) ;;
      *) return;;
esac
```
`$-` son los flags del shell; si contiene `i` es interactivo.

**Para qué sirve:** separar configuración interactiva (aliases, prompt) de la de login. Trampa real que vimos: comandos ejecutados por automatización (paramiko, scripts) corren con `$- = hBc` (sin `i`) → el `.bashrc` retorna en la línea 9 y todo lo que agregues al final **jamás corre**. Por eso los exports de CUDA van en `~/.profile`.

---

## 4. Symlinks y Debian alternatives

**Qué es:** `/usr/local/cuda → /etc/alternatives/cuda → /usr/local/cuda-12.6`. Una cadena de enlaces simbólicos gestionada por `update-alternatives`.

**Para qué sirve:** tener varias versiones instaladas (12.6, 12.x) y cambiar la activa sin reinstalar ni mover archivos. Apuntar al alias `/usr/local/cuda` en vez de a la versión fija te protege de upgrades.

---

## 5. Stack NVIDIA (driver, CUDA Toolkit, cuDNN, TensorRT, JetPack)

**Qué es cada uno:**
- **Driver NVIDIA (540.5):** el que habla con el hardware. Define la versión máxima de CUDA soportada (`nvidia-smi` → CUDA 12.6 en tu Jetson).
- **CUDA Toolkit (12.6.11):** compilador `nvcc`, headers y `nvcc` para escribir/correr código en GPU.
- **cuDNN (9.3.0):** librería de primitivas de redes neuronales (convoluciones) que usan PyTorch/TensorRT por debajo.
- **TensorRT (10.3):** optimizador que convierte un modelo en un motor rápido (FP16/INT8) para inferencia en el borde.
- **JetPack (R36.5):** el bundle de NVIDIA para Jetson que trae todo lo anterior ya compilado para `aarch64`.
- **aarch64:** arquitectura ARM de 64 bits (tu Jetson y tu Raspberry). Distinta de `x86_64` (tu PC): los binarios no son intercambiables, por eso el tutorial de Windows (`.exe`, VS Community, MSVC++) **no aplica** en Jetson.

**Tu estado:** driver 540.5 + Toolkit 12.6 + cuDNN 9.3 + TensorRT 10.3 + `build-essential`/`g++ 11.4` (equivalente Linux de MSVC++/VS Community). Falta solo PyTorch con CUDA (rueda de NVIDIA para ARM, no la de PyPI).

---

## 6. Red: IP, máscara, subred /24, DHCP

**Qué es:** tu red es `192.168.1.0/24`: 254 direcciones útiles (`.1`–`.254`). **DHCP** las reparte dinámicamente: por eso tu Jetson fue `.15` y ahora es `.21`. Si necesitas estabilidad, reserva la MAC en el router o pon IP fija.

---

## 7. ARP y tabla ARP

**Qué es:** protocolo que traduce IP → MAC ("¿quién tiene la 192.168.1.21?" → "yo, `9c:c7:d3:...`"). `arp -a` muestra la tabla aprendida.

**Para qué sirve en audeep:** `src/network.rs` (`arp_table_snapshot`) la lee sin necesitar `sudo`/raw sockets y asocia cada IP con su MAC física.

---

## 8. MAC y OUI (por qué "Locally Administered")

**Qué es:** la MAC tiene 6 bytes; los 3 primeros (OUI) identifican al fabricante (`88:a2:9e` = Raspberry Pi, `48:b0:2d` = NVIDIA, `24:a6:5e` = Tenda). Pero si el bit `0x02` del primer byte está prendido (ej: `9a`, `aa`), la MAC es **virtual/local** (Docker/WSL la inventan) y el OUI no dice nada real.

**Por eso ves** `Virtual — MAC local, marca real oculta` en varios hosts: audeep ya no inventa marca y te pide mirar `mDNS/hostname` en su lugar (`src/network.rs`, `lookup_vendor` + `infer_vendor_from_host`, sin IPs hardcodeadas).

---

## 9. Ping y TTL

**Qué es:** eco ICMP para saber si un host vive. El `TTL` delata el SO: `64` = Linux, `128` = Windows.

**Ejemplo real:** `192.168.1.21` respondió `TTL=64` → Linux (cuadra con Ubuntu de la Jetson); `.15` y `.23` dieron timeout → apagados o fuera de red.

---

## 10. Puertos TCP/UDP y banners

**Qué es:** cada equipo tiene 65.535 puertos por protocolo. Los comunes: `22` SSH, `80/443` web, `445` archivos (SMB), `3389` escritorio remoto, `5432` Postgres, `5900` VNC. Al conectar, muchos servicios anuncian un **banner** (`SSH-2.0-OpenSSH_8.9p1 Ubuntu`) que revela software y versión.

**Para qué sirve en audeep:** `src/scanner.rs` prueba 21 puertos (`COMMON_PORTS`) en paralelo con `tokio` y guarda el banner; `src/vuln.rs` lo cruza con la base de CVEs.

---

## 11. mDNS, SSDP, reverse DNS

**Qué es:**
- **mDNS:** resolución de nombres local sin servidor (`jetson-nano.local`), vía `mdns-sd`.
- **SSDP:** descubrimiento con `M-SEARCH` a `239.255.255.250:1900`; los aparatos responden con `LOCATION`/`SERVER`.
- **Reverse DNS:** traduce IP → nombre (`192.168.1.1` → `gpon.net`).

**Para qué sirve:** identificar marca/modelo real cuando la MAC es virtual. Si tu Jetson anunciara `jetson-nano.local` (con `avahi-daemon`), audeep la deduciría sola.

---

## 12. SNMP 161 public

**Qué es:** cuestionario estándar que traen routers/impresoras en el puerto `161`. `public` es la "contraseña" por defecto que muchos dejan puesta.

**Para qué sirve:** si responde, obtienes nombre, tiempo encendido e interfaces **sin instalar nada** (hardware remoto gratis). Si no responde o pide comunidad privada, no se insiste. Déjalo en `private` con clave larga en tus equipos.

---

## 13. SSH (llaves vs password, banners)

**Qué es:** acceso remoto cifrado al shell. Autenticación por password (lo que usas: `root123`) o por llave (`~/.ssh`, sin password tras `ssh-copy-id`).

**Para qué sirve aquí:** así entro a tu Jetson (`jetson-orin-nano@192.168.1.21`) a ejecutar diagnósticos. El banner `SSH-2.0-OpenSSH_*` ya dice versión de OpenSSH, útil para CVEs de SSH. Buenas prácticas: llave + deshabilitar `root` + cambiar passwords.

---

## 14. SMB y SMBv1 (EternalBlue)

**Qué es:** protocolo para compartir carpetas (`\\192.168.1.11\docs`, puerto `445`). **SMBv1** es la versión de 1983 con el fallo **EternalBlue** (`CVE-2017-0144`) que permite entrar sin password.

**Tu caso:** audeep marcó `CVE-2017-0144 crítica :445` en tu PC y en `.50`. Remedio: `Panel → Características de Windows → desmarcar Soporte SMB 1.0` (o `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`).

---

## 15. CVE, severidad y NVD

**Qué es:** identificador público de una vulnerabilidad (`CVE-2017-0144`), con severidad `crítica/alta/media/baja` según CVSS. **NVD** (`nvd.nist.gov`) es la base oficial.

**En audeep:** `assets/cve.db` (SQLite offline, 7 curados + los que traigas con `xtask fetch-nvd --limit 30 --merge`) se cruza por puerto y banner. La columna `Vulns` y el drawer muestran CVE + puerto + descripción + recomendación + link NVD.

---

## 16. Qué hace cada módulo de audeep

| Módulo | Hace |
|---|---|
| `hardware.rs` | Inventario **local** (`sysinfo`): CPU/RAM/discos/IFaces/sensores. Solo del equipo donde corre. |
| `network.rs` | Descubrimiento de **toda la red**: subnet, TCP+ping+ARP, OUI, reverse DNS, mDNS/SSDP, inferencia sin hardcode. |
| `scanner.rs` | 21 puertos en paralelo + banners. |
| `vuln.rs` | Cruce puertos/banners contra `cve.db` (con fallback a JSON). |
| `report.rs` | HTML crema offline + JSON. |
| `serve.rs` | Server `0.0.0.0:8766`: `/` `/json` `/health` `/docs`, cache 12s. |
| `audeep-web` | Front React `5111` (Chart.js) que lee `/json` cada 5s. |

---

## 17. Los 21 puertos que se prueban

**Qué es:** 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 135 (MSRPC), 139 (NetBIOS), 143 (IMAP), 443 (HTTPS), 445 (SMB), 993/995 (IMAP/POP3S), 1723 (PPTP VPN), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 5900 (VNC), 8080/8443 (HTTP alt).

**Para qué sirve:** saber qué cubre el scan y qué no: un servicio en otro puerto (ej: 3000, 8000) no se verá. Son los más atacados, no todos (`COMMON_PORTS` en `scanner.rs`).

---

## 18. xtask: ampliar la base de vulnerabilidades

**Qué es:** mini-herramienta Rust con `build-cve` (reconstruye `cve.db` del JSON local) y `fetch-nvd` (descarga CVEs reales de la API NVD 2.0, ventana 90 días, `--limit` hasta 2000, `--merge` conserva los 7 curados).

**Para qué sirve:** pasar de 7 a 37+ CVEs sin editar código. Tras traerlos hay que recompilar para que queden embebidos (`xtask/src/main.rs`).

---

## 19. Cache de 12s y estado «escaneando»

**Qué es:** el primer `/json` tarda ~10s (scan en background, responde `202 {status:scanning}`) y el resultado se cachea 12s.

**Para qué sirve:** «Conectando…» no es error, es el primer scan. El log muestra `[scan] Generando/Listo` con duración y nº de hosts (`serve.rs`).

---

## 20. Cómo leer el dashboard

**Qué es:** 4 stats, 3 gráficas (vendors, dona de severidad, puertos), buscador + filtro por severidad («Sanos» incluidos), tabla de 9 columnas, drawer por host con banners y links NVD, doble click copia la IP, polling a `/json` cada 5s.

---

## 21. Seguridad del propio serve

**Qué es:** el 8766 **no pide contraseña** y escucha en toda tu red (`0.0.0.0`), exponiendo tu inventario en `/json`.

**Para qué sirve saberlo:** úsalo solo en red local de confianza; no lo expongas a internet (pendiente: JWT + TLS).

---

## 22. Dónde vive cada cosa

**Qué es:** dos repos: `audeep` (Rust: CLI + serve 8766) y `audeep-web` (React: front 5111, sin datos propios, todo de `/json`).

**Para qué sirve:** si el front se queda en «Conectando…», mira el back. Con `VITE_AUDEEP_URL` apuntas el front a otra IP (ej: la Raspberry).

---

*Origen: `knowledge/dispositivo_auditor.md` + `docs/architecture.md` + `docs/guia-conceptos.md`. Este archivo es la referencia técnica; la guía simple vive en `guia-conceptos.md`.*
