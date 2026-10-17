# AuDeep — Guía Simple: qué hace cada cosa (sin tecnicismos)

> Si nunca auditase una red: acá va **concepto por concepto** qué hace AuDeep y para qué sirve, con analogías de la vida real. Versión 0.2.

---

## 1. Hardware — "¿qué tengo en mi PC?"

**Analogía:** abrir el capó y mirar motor, nafta y ruedas.

- **Qué hace:** lee tu equipo y te dice sistema (Windows 11), procesador (AMD Ryzen 9), memoria (63 GB), discos (C: 475 GB), las placas de red con su **dirección física y su IP**, y temperaturas si el equipo tiene sensores.
- **Para qué:** saber con qué contás. Es tu inventario base, y sirve para comparar cuando algo se pone lento.
- **Dónde lo ves:** tarjeta "Hardware" del reporte, o `audeep --no-scan` si querés solo esto.

---

## 2. Red — "¿quién está conectado a mi WiFi?"

**Analogía:** tocar timbre en cada puerta del edificio para ver quién vive ahí.

- **Qué hace:** descubre los aparatos de tu red y averigua quién es cada uno. El orden importa:
  1. **Pregunta en el idioma de las placas (ARP):** "¿quién tiene la 192.168.1.10?" y la placa contesta con su dirección física. Es la forma más rápida y fiable, y hace aparecer también a los aparatos mudos (cámaras, sensores, enchufes).
  2. **Toca puertas (TCP):** si alguno contesta "ese servicio no está", ya sabemos que el aparato existe.
  3. **Grita "¿hay alguien?" (ping):** solo cuenta si vuelve el eco.
  4. **Traduce la marca (OUI):** los primeros 3 bytes de la dirección física dicen el fabricante (`24:a6:5e` = Tenda, `90:dd:5d` = Espressif).
  5. **Pregunta bonito (mDNS/SSDP):** algunos aparatos se presentan solos con su nombre real (`impresora-hp.local`) o con su dirección web.
  6. **Traduce IP a nombre (reverse DNS).**
- **Lo importante:** cada dato viene con **su fuente** ("lo dijo el registro de fabricantes", "lo deduje del nombre", "me lo dijo el propio equipo"). No inventa marcas.
- **Para qué:** ver intrusos, impresoras, cámaras, teles, tu Raspberry.
- **Dónde lo ves:** la tabla "Red" y el gráfico de fabricantes.
- **Redes grandes:** lee la máscara real de tu red en vez de suponer 254 direcciones, y tiene un techo para no quedarse escaneando para siempre.

---

## 3. Puertos — "¿qué puertas tiene abiertas cada vecino?"

**Analogía:** cada aparato tiene 65.535 puertas; algunas abiertas (22 = acceso remoto, 80 = web, 445 = compartir archivos).

- **Qué hace:** prueba **21 puertas comunes** en cada aparato vivo, en paralelo, y cuando alguna está abierta lee el "letrero" que anuncia el servicio (`SSH-2.0-dropbear_2022.83`).
- **Detalle fino:** solo lee letreros donde el servicio saluda primero. En las puertas web no pierde tiempo esperando un saludo que nunca llega.
- **Para qué:** saber si tu router tiene la web abierta, si tu PC comparte archivos, si hay una base de datos expuesta.
- **Dónde lo ves:** columna "Puertos" (con el letrero cuando existe).
- **Personalizable:** la lista de puertas se cambia en `audeep.json` (ver punto 9).

---

## 4. Vulnerabilidades — "¿alguna puerta es peligrosa de verdad?"

**Analogía:** antes de gritar "¡te van a robar!", AuDeep golpea la puerta y comprueba.

- **Qué hace:** cruza lo que encontró contra una lista de fallos conocidos, pero **no alcanza con ver una puerta abierta**:
  - **SMB (445):** habla el protocolo de verdad y mira qué versión acepta el equipo. Si contesta la versión nueva, **no hay problema** y no te asusta. Solo si acepta la versión vieja (SMB1) te marca EternalBlue.
  - **SSH (22):** lee el letrero y compara la **versión** contra los rangos publicados (`OpenSSH 7.0 - 7.6`, `8.0 - 9.3`, etc.), en vez de buscar pedazos de texto.
  - **Web/TLS:** compara el letrero con lo que se sabe (`Apache 2.4.49`, `OpenSSL 1.0.1`).
- **Cuánto sabe:** cada aviso dice **confirmado** (lo comprobé yo), **probable** (me lo dijo el propio equipo) o **sospecha** (solo vi una puerta abierta), y muestra **la evidencia**.
- **Para qué:** priorizar. `crítica` = parche ya; `sospecha` = revisá cuando puedas. No es un antivirus: es un aviso con fundamento.
- **Dónde lo ves:** columna "Hallazgos", con severidad, confianza y evidencia.
- **Ampliable:** `xtask fetch-nvd --limit 30 --merge` baja los fallos recientes de la base oficial y los suma a los curados.

---

## 5. Riesgo — "¿por dónde empiezo?"

**Analogía:** el semáforo, no la lista alfabética.

- **Qué hace:** a cada aparato le pone un puntaje de 0 a 100 combinando tres cosas: lo grave de los hallazgos, **cuánta confianza** tiene en ellos, y qué servicios sensibles tiene expuestos (escritorio remoto, Telnet, VNC, SMB, bases de datos).
- **Resultado:** nivel `sin riesgo / bajo / medio / alto / crítico` y los motivos por escrito. Ejemplo real: *"mayor riesgo: 192.168.1.7, puntaje 30 (medio) — SMB, PostgreSQL, MSRPC y NetBIOS expuestos"*.
- **Para qué:** que lo importante no quede enterrado en el medio de una tabla. El reporte se ordena por riesgo, no por número de IP.

---

## 6. Cambios — "¿qué pasó desde la última vez?"

**Analogía:** el sereno que anota quién entró y quién se fue.

- **Qué hace:** guarda cada escaneo en un archivito y compara con el anterior. Te avisa:
  - **Aparato nuevo** en tu red.
  - **Aparato que ya no responde.**
  - **Puerta que se abrió** en un aparato que ya conocías.
  - **La misma dirección física en varias IP** → eso pasa cuando hay máquinas virtuales (VMware, WSL) o cuando alguien está **suplantando** equipos en la red.
  - **Cambió la dirección física de tu router** → señal clásica de que alguien se metió en el medio de la comunicación.
- **Para qué:** una foto no sirve para vigilar; saber qué cambió, sí. En su primera corrida AuDeep encontró 7 direcciones distintas usando la **misma** dirección física.
- **Dónde lo ves:** panel "Cambios desde el último escaneo" arriba de la tabla, y en la consola mientras corre.
- **Se guarda en:** `audeep_history.db` (podés moverlo con `--history` o no usarlo con `--no-history`).

---

## 7. Reporte — "el papel que le das a tu jefe"

**Analogía:** el resumen que dejás sobre la mesa.

- **Qué hace:** arma dos archivos: **JSON** (para programas) y **HTML** (para humanos, con estilos, sin internet, funciona con doble click).
- **Qué trae el HTML:** cinco números arriba (aparatos, hallazgos, críticos, fabricantes, puertos), gráficos, la tabla **ordenada por riesgo**, los avisos de cambios, el detalle de discos y placas de red, y **botones para exportar a Excel (CSV) y a JSONL**.
- **Para qué:** guardarlo en un pendrive, mandarlo por mail o abrirlo sin depender de nada.

---

## 8. Serve — "el camarero que te lo sirve"

**Analogía:** el que te trae el reporte a la mesa sin que vayas a la cocina.

- **Qué hace:** levanta una página web chiquita con el reporte en vivo: la página principal, los datos en `/json`, una señal de vida en `/health`, la documentación en `/docs`, y `/scan` para forzar un escaneo nuevo.
- **Seguro por defecto:** atiende **solo a tu propia máquina**. Para verlo desde el celular hay que pedirlo a propósito (`--serve 0.0.0.0:8766`) y conviene ponerle contraseña (`--serve-token`).
- **Sin plaga:** refresca el reporte cada 60 segundos (configurable con `--serve-interval`), no cada 12 como antes.
- **Cómo:** `audeep --serve` y abrís `http://127.0.0.1:8766/`.

---

## 9. Config — "el archivito para ajustarlo"

**Analogía:** las preferencias del programa.

- **Qué hace:** si dejás un archivo `audeep.json` junto al programa, AuDeep lo lee y ajusta: cuánto esperar por puerta, cuántas tareas en paralelo, cuánto escuchar los anuncios de la red, **qué puertas mirar** y **qué equipos ignorar**.
- **Ejemplo:**
  ```json
  { "probe_timeout_ms": 400, "ports": [22, 80, 443, 445, 3389], "exclude": ["192.168.1.50"] }
  ```
- **Para qué:** que no tengas que recompilar nada para adaptarlo a tu red. Todos los campos son opcionales y los valores absurdos se corrigen solos.

---

## 10. Pi / USB — "el aparato que hace todo solo"

**Analogía:** dejás una cajita enchufada y te trae el papel.

- **Qué hace:** en una Raspberry arranca solo cuando hay red, escanea, guarda el reporte y, cuando metés un pendrive, lo copia ahí y parpadea un LED para avisarte. También hay una versión en Docker.
- **Para qué:** auditar una red sin llevar tu PC: solo corriente y un cable.

---

## 11. Lo que NO hace (para que no te sorprenda)

- **No es un antivirus:** no limpia ni arregla nada, no entra a los equipos. Solo mira desde afuera.
- **No explota nada:** no ataca, no rompe, no se conecta a servicios de forma agresiva.
- **No adivina el parche exacto:** cuando un aviso depende del nivel de actualización (por ejemplo el fallo del escritorio remoto, BlueKeep), te lo marca como **sospecha** y te dice que verifiques, en vez de asustarte.
- **No consulta SNMP (161)**: esa puerta no está en su lista; si la necesitás, se agrega en `audeep.json`.
- **No ve lo que la red esconde:** si un aparato bloquea todo y no responde ni al saludo de las placas, no aparece.

---

**En una frase:** AuDeep es *un solo programa que te dice qué tenés, quién está con vos en la red, qué puertas tiene abiertas cada uno, si eso es peligroso de verdad, qué cambió desde ayer y por dónde empezar a arreglarlo — sin internet y sin ser experto*.
