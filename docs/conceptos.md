# AuDeep — Conceptos: qué es cada cosa y para qué sirve

> Referencia técnica. Cada concepto: definición, para qué sirve y cómo lo usa AuDeep.
> **Verificado con las corridas de la v0.2 sobre la red `192.168.1.0/24`** (11 equipos vivos, 6,8 s, 0 falsos positivos de SMB).
> Ver también la guía sin tecnicismos: `docs/guia-conceptos.md`.

---

# Parte 1 — Conceptos generales

## 1. PATH

**Qué es:** variable de entorno con la lista ordenada de directorios donde el shell busca un comando cuando lo escribís sin ruta.

**Para qué sirve:** evita escribir `/usr/local/cuda-12.6/bin/nvcc` cada vez; basta `nvcc`. El shell prueba cada directorio en orden y ejecuta la primera coincidencia (`type -a` / `which -a` muestran cuál ganó).

---

## 2. LD_LIBRARY_PATH

**Qué es:** el gemelo del PATH pero para **librerías compartidas** (`.so`): `libcudnn.so.9`, `libcublas.so`, etc.

**Para qué sirve:** cuando un programa arranca, el linker (`ld.so`) busca ahí las librerías que necesita. Sin esto, compila bien pero al correr falla con `error while loading shared libraries`.

---

## 3. Archivos de arranque del shell (`.bashrc`, `.profile`) y el guard `case $-`

**Qué es:** scripts que bash lee al arrancar para definir el entorno. `~/.profile` lo leen los **login shells**; `~/.bashrc` los interactivos. Un `.bashrc` típico empieza con:

```bash
case $- in
    *i*) ;;
      *) return;;
esac
```

**Para qué sirve:** separar configuración interactiva (aliases, prompt) de la de login. Trampa clásica: los comandos ejecutados por automatización corren con `$- = hBc` (sin `i`), el `.bashrc` retorna temprano y todo lo que agregues al final **jamás corre**. Por eso los exports de CUDA van en `~/.profile`.

---

## 4. Symlinks y Debian alternatives

**Qué es:** `/usr/local/cuda → /etc/alternatives/cuda → /usr/local/cuda-12.6`. Una cadena de enlaces simbólicos gestionada por `update-alternatives`.

**Para qué sirve:** tener varias versiones instaladas y cambiar la activa sin reinstalar. Apuntar al alias `/usr/local/cuda` en vez de a la versión fija te protege de los upgrades.

---

## 5. Stack NVIDIA (driver, CUDA Toolkit, cuDNN, TensorRT, JetPack)

- **Driver NVIDIA:** habla con el hardware y define la versión máxima de CUDA soportada (`nvidia-smi`).
- **CUDA Toolkit:** compilador `nvcc` y headers para escribir/correr código en GPU.
- **cuDNN:** primitivas de redes neuronales (convoluciones) que usan PyTorch/TensorRT por debajo.
- **TensorRT:** optimizador que convierte un modelo en un motor rápido (FP16/INT8) para inferencia en el borde.
- **JetPack:** el bundle de NVIDIA para Jetson que trae todo lo anterior ya compilado para `aarch64`.
- **aarch64:** arquitectura ARM de 64 bits (Jetson, Raspberry). No es intercambiable con `x86_64` (tu PC): por eso el tutorial de Windows (`.exe`, MSVC++) **no aplica** en Jetson.

---

# Parte 2 — Red y seguridad

## 6. IP, máscara, subred y DHCP

**Qué es:** una red se define por su dirección y su **máscara**, que dice cuántas direcciones entran (`192.168.1.0/24` = 254 útiles, `.1`–`.254`). **DHCP** las reparte dinámicamente: por eso un equipo puede ser `.15` hoy y `.21` mañana.

**En AuDeep:** ya **no asume `/24`**. Lee la máscara real de tu interfaz (`if-addrs`) y calcula la red; en redes enormes acota el barrido al `/24` propio y tiene un techo de equipos para no quedarse escaneando eternamente. Si necesitás estabilidad de IP, reservá la MAC en el router.

---

## 7. ARP y tabla ARP

**Qué es:** protocolo que traduce IP → MAC ("¿quién tiene la 192.168.1.10?" → "yo, `02:00:5e:...`"). `arp -a` (Windows) o `/proc/net/arp` (Linux) muestran la tabla aprendida.

**En AuDeep:** es la **primera** vía de descubrimiento, no la última. `src/arp.rs` lee y parsea la tabla (dos formatos y cualquier idioma del campo *Type*), validando que la MAC sean 6 octetos hexadecimales y descartando multicast/broadcast. `network::arp_sweep()` fuerza la resolución mandando un paquete a cada dirección de la red y vuelve a leer: así aparecen en segundos los equipos **que no exponen ningún puerto** (cámaras, sensores, enchufes). No necesita `sudo` ni raw sockets.

---

## 8. MAC, OUI y "Locally Administered"

**Qué es:** la MAC tiene 6 bytes; los 3 primeros (OUI) identifican al fabricante (`88:a2:9e` = Raspberry Pi, `48:b0:2d` = NVIDIA, `24:a6:5e` = Tenda). Si el bit `0x02` del primer byte está prendido (ej: `9a`, `aa`), la MAC es **aleatoria/local** (Docker/WSL/VM las inventan) y el registro OUI **no dice nada real**.

**En AuDeep:** `lookup_vendor_guess()` resuelve en orden de confianza — lista curada → **bit de MAC local** → registro de ~40.000 prefijos — y devuelve siempre **de dónde salió el dato**: `oui`, `oui-local`, `hostname`, `mdns`, `ssdp`, `banner`, `puerto`, `http`. Por eso en el reporte ves `vendor (fuente)` y `"MAC local/aleatoria — fabricante oculto"` en vez de una marca inventada. La deducción por nombre usa tokens completos (`contains_token`), así que `miguel-pc` ya no matchea "mi" como Xiaomi.

---

## 9. Ping y TTL

**Qué es:** eco ICMP para saber si un equipo vive. El `TTL` delata el sistema: `64` = Linux, `128` = Windows.

**En AuDeep:** el ping es el **último** recurso y solo cuenta si la salida trae **`TTL=`**, porque es lo único que no se traduce. La versión anterior buscaba textos como `"Request timed out"`: en un Windows en otro idioma esa cadena no existe y **todo equipo muerto quedaba como vivo** (así aparecían 69 equipos donde hay 11). Además, un rechazo de TCP (RST) también cuenta como vida: significa que alguien mantuvo la conexión.

---

## 10. Puertos TCP y banners

**Qué es:** cada equipo tiene 65.535 puertos por protocolo. Los comunes: `22` SSH, `80/443` web, `445` archivos (SMB), `3389` escritorio remoto, `5432` Postgres, `5900` VNC. Al conectar, muchos servicios anuncian un **banner** (`SSH-2.0-OpenSSH_8.9p1`) que revela software y versión.

**En AuDeep:** `src/scanner.rs` prueba 21 puertos en paralelo con `tokio` y clasifica cada uno en tres estados: **abierto** (hay servicio), **rechazado** (el equipo existe pero la puerta está cerrada) y **filtrado** (silencio: no se puede afirmar nada). El banner se lee **solo** donde el servicio saluda primero (22, 21, 25, 3306…): en 80/443 el servidor espera la petición y leer sería perder 800 ms por equipo. La lista de puertos se cambia con `audeep.json`.

---

## 11. mDNS, SSDP y reverse DNS

**Qué es:**
- **mDNS:** resolución de nombres local sin servidor (`impresora-hp.local`), vía `mdns-sd`.
- **SSDP:** descubrimiento con `M-SEARCH` a `239.255.255.250:1900`; los equipos responden con `LOCATION`/`SERVER`.
- **Reverse DNS:** traduce IP → nombre (`192.168.1.1` → `gpon.net`).

**En AuDeep:** sirven para **identificar de verdad** cuando la MAC es virtual, y aportan el nombre real al reporte. También descubren equipos que no responden a nada más.

---

## 12. SNMP 161 public

**Qué es:** cuestionario estándar que traen routers/impresoras en el puerto `161`. `public` es la "contraseña" por defecto que muchos dejan puesta.

**Importante en AuDeep:** **no consulta SNMP**: el 161 no está en su lista de puertos. Si lo necesitás, agregalo en `audeep.json`. Esto es contexto para que sepas qué más se puede mirar en una red.

---

## 13. SSH: llaves vs password, y por qué importa la versión

**Qué es:** acceso remoto cifrado al shell. Autenticación por password o por llave (`~/.ssh`, sin password tras `ssh-copy-id`).

**En AuDeep:** lee el banner (`SSH-2.0-OpenSSH_7.2p2 Ubuntu…`), lo parte en **producto + versión** (`parse_ssh_banner`) y compara la versión contra **rangos publicados** (`version_in_range`): `7.0–7.6` para el fallo de enumeración de usuarios, `8.0–9.3` para el de `ssh-agent`, `6.0–7.1` para el de roaming. Antes se buscaban pedazos de texto (`"OpenSSH_7.2"`), que fallaban con `7.2p2` o `7.6p1`. Buenas prácticas: llave + deshabilitar `root` + cambiar passwords.

---

## 14. SMB, SMBv1 y EternalBlue

**Qué es:** protocolo para compartir carpetas (puerto `445`). **SMBv1** es la versión vieja con el fallo **EternalBlue** (`CVE-2017-0144`), que permite ejecutar código sin autenticarse.

**En AuDeep:** acá está el cambio más importante de la v0.2. Antes, **ver el 445 abierto** alcanzaba para marcar `crítica` (y en una red doméstica eso son falsas alarmas). Ahora `src/probe.rs` **negocia el protocolo de verdad**: manda un pedido de negociación de 73 bytes y mira qué dialecto acepta el equipo. Si contesta SMB2/3 (lo normal hoy), **no se marca nada**; solo si acepta SMB1 aparece el hallazgo, con confianza **confirmado** y la evidencia ("negociación SMB real: SMB1 habilitado"). Remedio si acepta SMB1: `Panel → Características de Windows → desmarcar Soporte SMB 1.0`, o `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`.

---

# Parte 3 — AuDeep por dentro

## 15. CVE, severidad, confianza y NVD

**Qué es:** un CVE es el identificador público de un fallo (`CVE-2017-0144`), con severidad `crítica/alta/media/baja` según CVSS. **NVD** (`nvd.nist.gov`) es la base oficial.

**En AuDeep:** la base se arma mezclando dos fuentes: las **reglas curadas** en `assets/vuln_db.json` (que incluyen **rangos de versión** y la confianza declarada) y los CVEs extra de `assets/cve.db` (los que bajes con `xtask fetch-nvd --limit 30 --merge`), sin repetir identificadores. Se cachea **una sola vez por proceso** (`OnceLock`): antes se reconstruía en cada equipo y escribía un archivo temporal por equipo.

Cada hallazgo dice con qué certeza se afirma:

| Confianza | Cuándo | Ejemplo |
|---|---|---|
| **confirmado** | Se probó activamente | SMB1 negociado en el 445 |
| **probable** | Lo declara el propio equipo | banner con versión afectada |
| **sospecha** | Solo hay un puerto abierto | RDP en 3389 sin poder ver el parche |

---

## 16. Qué hace cada módulo

| Módulo | Hace |
|---|---|
| `hardware.rs` | Inventario **local** (`sysinfo`): CPU/RAM/discos/interfaces (con sus **IPs** vía `if-addrs`) y sensores. |
| `arp.rs` | Lee y parsea la tabla ARP: dos formatos, cualquier idioma, MAC validada, sin multicast/broadcast. |
| `network.rs` | Descubrimiento **ARP-first**, subred real por máscara, TCP de 3 estados, ping por `TTL`, OUI + deducción de marca con fuente, reverse DNS, mDNS/SSDP. |
| `scanner.rs` | 21 puertos (o los de la config) en paralelo, banners selectivos y negociación SMB del 445. |
| `probe.rs` | Sondas de confirmación: negociación SMB1 y parseo/comparación de versiones SSH. |
| `vuln.rs` | Base curada + SQLite (cacheada con `OnceLock`), reglas por puerto/banner/versión, y `Finding` con confianza y evidencia. |
| `risk.rs` | Puntaje de riesgo 0-100 por equipo, con nivel y motivos. |
| `history.rs` | Historial SQLite: diff entre escaneos y anomalías de capa 2 (MAC repetida, cambio de router). |
| `report.rs` | JSON + HTML crema offline (riesgo, evidencia, eventos, export CSV/JSONL). |
| `serve.rs` | Servidor: `/`, `/json`, `/health`, `/scan`, `/docs`, `/docs/conceptos`; caché con TTL, `ETag`, token opcional. |
| `config.rs` | `audeep.json`: timeouts, concurrencia, puertos y exclusiones. |
| `audeep-web` | Front React `5111` (Chart.js) que lee `/json` cada 5 s. |

---

## 17. Los 21 puertos que se prueban

21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 135 (MSRPC), 139 (NetBIOS), 143 (IMAP), 443 (HTTPS), 445 (SMB), 993/995 (IMAP/POP3S), 1723 (PPTP VPN), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 5900 (VNC), 8080/8443 (HTTP alternativos).

**Para qué sirve saberlo:** son los más atacados, no todos (`COMMON_PORTS` en `scanner.rs`). Un servicio en otro puerto (3000, 8000, 161…) **no se verá** salvo que lo agregues en `audeep.json`.

---

## 18. xtask: ampliar la base de vulnerabilidades

**Qué es:** mini-herramienta Rust con `build-cve` (reconstruye `cve.db` desde el JSON curado) y `fetch-nvd` (baja CVEs reales de la API NVD 2.0, ventana de 90 días, `--limit` hasta 2000, `--merge` conserva los curados).

**Para qué sirve:** pasar de 7 a 37+ CVEs sin editar código. Tras traerlos hay que recompilar para que queden embebidos.

---

## 19. Caché del reporte y estado "escaneando"

**Qué es:** el primer `/json` responde `202 {status:scanning}` (el escaneo corre en segundo plano) y el resultado se guarda en caché durante **60 s** por defecto (`--serve-interval`). Si el caché venció, se regenera de fondo **mientras se sigue sirviendo el anterior**, así la página nunca queda vacía. `/scan` (o `?force=1`) fuerza un escaneo ya.

**Para qué sirve saberlo:** "Conectando…" no es un error, es el primer escaneo. El log muestra `[scan] regenerando…` y `[scan] listo en X s`. La versión anterior re-escaneaba cada 12 s sin parar.

---

## 20. Cómo leer el reporte

**Qué es:** cinco números arriba (equipos, hallazgos, **equipos críticos**, fabricantes, puertos), tres gráficos (fabricantes, dona de severidad, puertos), y la tabla **ordenada por riesgo** con: IP, nombre, MAC, fabricante (con su fuente), **riesgo (puntaje + nivel + motivos)**, puertos con banner, hallazgos con severidad + **confianza** + **evidencia**, y mDNS/SSDP. Arriba de todo, el panel de **cambios** desde el escaneo anterior.

También hay: filtro por riesgo, por severidad y por fabricante, buscador libre, doble click para copiar la IP, y botones de **export a CSV** (para Excel) y **JSONL**.

---

## 21. Seguridad del propio serve

**Qué es (v0.2):** por defecto el servidor escucha **solo en `127.0.0.1`**, o sea que únicamente tu propia máquina lo ve. Nada de publicar el inventario a toda la red sin querer.

**Si lo querés desde el celular o en modo AP:** pasá la dirección a propósito (`--serve 0.0.0.0:8766`) y poné `--serve-token <CLAVE>`; desde ahí las consultas necesitan `?token=CLAVE` o la cabecera `X-Auth-Token`. Además responde con `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` y `ETag` para no reenviar el mismo reporte.

**Pendiente:** HTTPS/TLS propio (hoy va en claro dentro de la red local).

---

## 22. Dónde vive cada cosa

**Qué es:** dos repos: `audeep` (Rust: CLI + serve 8766) y `audeep-web` (React: front 5111, sin datos propios, todo de `/json`).

**Para qué sirve:** si el front queda en "Conectando…", mirá el back (y su caché de 60 s). Con `VITE_AUDEEP_URL` apuntás el front a otra IP (por ejemplo la Raspberry). Los campos nuevos del JSON (`vendor_source`, `confidence`, `evidence`, `events`, `critical_hosts`) son **aditivos**: el front sigue funcionando aunque todavía no los muestre.

---

## 23. Score de riesgo

**Qué es:** un puntaje de 0 a 100 por equipo que combina severidad, **certeza** y exposición de servicios.

**Cómo se calcula:** una crítica confirmada pesa 40 puntos; una crítica sin confirmar, 30; una alta confirmada, 25; una alta sin confirmar, 18; media 12; baja 5. Después suma exposición: RDP 15, Telnet 15, VNC 12, SMB 10, MySQL 10, PostgreSQL 10, FTP 8, MSRPC/NetBIOS/PPTP 5. El total se topea en 100 y se traduce a nivel: `sin riesgo` (0), `bajo` (1-19), `medio` (20-39), `alto` (40-59), `crítico` (60+).

**Para qué sirve:** una lista de hallazgos no dice por dónde empezar; el puntaje sí, y el reporte se ordena por él.

---

## 24. Historial, diff y anomalías de capa 2

**Qué es:** una base SQLite (`audeep_history.db`) con cada escaneo y sus equipos, que se poda a los últimos 200 escaneos.

**Qué te dice al comparar con el anterior:** equipo **nuevo**, equipo que **desapareció**, **puerto nuevo** en un equipo conocido, la **misma MAC en varias IP** (virtualización o ARP spoofing) y el **cambio de MAC del router** (posible intermediario). El router se identifica por heurística: la IP más baja de la red (casi siempre `.1`).

**Para qué sirve:** una foto suelta no sirve para vigilar. Con historial, AuDeep pasa de "inventario" a "aviso de cambios". Se desactiva con `--no-history` y se mueve con `--history <ruta>`.

---

## 25. Configuración (`audeep.json`)

**Qué es:** un archivo JSON opcional junto al programa (o el que pases con `--config`) con cinco campos, todos opcionales:

```json
{
  "probe_timeout_ms": 400,
  "concurrency": 64,
  "mdns_timeout_ms": 1200,
  "ports": [21, 22, 80, 443, 445, 3389],
  "exclude": ["192.168.1.50"]
}
```

**Para qué sirve:** adaptar el escaneo sin recompilar. Los valores se validan y normalizan (puertos ordenados y sin repetidos, timeouts y concurrencia dentro de rango), así que un archivo mal escrito no rompe el escaneo. Ver `audeep.example.json`.

---

## 26. Estados de un sondeo (por qué "no contesta" y "contesta que no" no son lo mismo)

**Qué es:** cada puerto se clasifica en tres estados:

- **Abierto:** el servicio está escuchando.
- **Rechazado (RST):** el equipo **existe** y contestó "acá no hay nadie en esa puerta".
- **Filtrado:** silencio. Puede ser que no exista, que haya un firewall, o que esté apagado.

**Para qué sirve:** mezclar "rechazado" con "filtrado" hace perder equipos vivos (y fue un bug real de la v0.1). En Windows, además, una conexión rechazada puede llegar como *timeout* aunque el sistema operativo haya visto el rechazo: por eso el veredicto de vida en la red se apoya en **ARP** y, como respaldo, en el `TTL` del ping — no en este detalle.

---

**En una frase:** AuDeep dice qué hay, quién está, qué puertas están abiertas, **si eso es peligroso de verdad**, cuánta confianza tiene en cada afirmación, qué cambió desde el escaneo anterior y por dónde empezar — offline, en un solo binario.
