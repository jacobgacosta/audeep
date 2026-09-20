# AuDeep — Guía Simple: Qué Hace Cada Cosa (Sin Tecnicismos)

> Si nunca has auditado una red, esta guía te explica **concepto por concepto** qué hace AuDeep, con analogías de la vida real.

## 1. Hardware — "¿Qué tengo en mi PC?"
**Analogía:** Como abrir el capó del coche y ver motor, gasolina, ruedas.

- **Qué hace:** Lee tu PC (Windows/Linux/Pi) y te dice: qué sistema tienes (Windows 11), qué procesador (AMD Ryzen 9), cuánta RAM (63GB), discos (C: 475GB), tarjetas de red (Wi-Fi MAC), y temperatura si hay sensores.
- **Para qué:** Saber si tu PC aguanta el trabajo, si tiene poco disco, o si se calienta. Es tu **inventario base**.
- **Dónde lo ves:** En el dashboard `Hardware — me` o `audeep --no-scan`.

## 2. Red — "¿Quién está conectado a mi WiFi?"
**Analogía:** Como tocar puerta por puerta en tu edificio para ver quién vive ahí.

- **Qué hace:** Descubre todos los aparatos en tu red `192.168.1.0/24` (hasta 254). Usa 4 trucos:
  - **TCP 80/445/22/53:** Toca 4 puertas rápidas (web, archivos, SSH, DNS). Si abre, está vivo.
  - **Ping:** Grita "¿hay alguien?" y espera eco `TTL`.
  - **ARP:** Pregunta "¿quién tiene esta IP?" y la tarjeta responde con su MAC.
  - **OUI:** Los 3 primeros bytes de la MAC dicen la marca (24:a6:5e = Tenda, 90:dd:5d = Espressif).
  - **mDNS/SSDP:** Pregunta bonito "¿quién eres?" y algunos responden `raspi5.local` o `LOCATION: http://...`.
  - **Reverse DNS:** Traduce `192.168.1.1` → `gpon.net`.
- **Para qué:** Ver intrusos, impresoras, cámaras, teles, o tu Pi `raspi5.local`.
- **Dónde lo ves:** Tabla `Red — 14 vivos` + gráficos Vendors.

## 3. Escáner de Puertos — "¿Qué puertas tiene abiertas cada vecino?"
**Analogía:** Cada aparato tiene 65.535 puertas; algunas abiertas (22 SSH, 80 web, 445 archivos).

- **Qué hace:** Prueba 21 puertas comunes en cada aparato vivo, en paralelo (64 a la vez, 800ms). Si abre, lee el letrero `banner` (ej: `SSH-2.0-dropbear_2022.83`).
- **Para qué:** Saber si tu router tiene web abierta, si tu PC expone archivos, si hay una base de datos `5432`.
- **Dónde lo ves:** Columna `Puertos` con `22 (SSH) open`.

## 4. Vulnerabilidades — "¿Alguna puerta es peligrosa?"
**Analogía:** Como comparar el letrero de la puerta con una lista de robos conocidos.

- **Qué hace:** Tiene una lista offline `cve.db` SQLite con 7 fallos famosos (ej: `CVE-2017-0144` EternalBlue en 445, `CVE-2014-0160` Heartbleed). Si tu aparato tiene `445 open`, te avisa `crítica`.
- **Para qué:** Priorizar: `crítica` = parche ya, `alta` = pronto. No es un antivirus, es un aviso.
- **Dónde lo ves:** Columna `Vulns` con `CVE-2017-0144 crítica :445` + cajita `NVD` link. Con `xtask fetch-nvd --limit 30 --merge` traes 30 más recientes.

## 5. Reporte — "El papel que le das a tu jefe"
**Analogía:** El resumen que dejas en la mesa.

- **Qué hace:** Junta hardware + red + puertos + vulns en 2 archivos: `JSON` (para máquinas) y `HTML crema` (para humanos, sin internet, `file://`).
- **Para qué:** Guardarlo en USB, mandarlo, o verlo en `http://127.0.0.1:8766/` (crema hack) o `http://127.0.0.1:5111/` (React dinámico).
- **Dónde lo ves:** `audeep_reporte.html` (doble click) o dashboard.

## 6. Serve — "El camarero que te lo sirve"
**Analogía:** El que te trae el reporte a la mesa sin que vayas a la cocina.

- **Qué hace:** Levanta un mini servidor en `0.0.0.0:8766` con 3 rutas: `/` (HTML mamón), `/json` (datos), `/health` (ok), `/docs` (esta guía). Con cache 12s y `CORS *` para que `5111` lo lea.
- **Para qué:** Verlo en vivo desde tu móvil en `http://192.168.1.50:8766/` o desde `5111` sin copiar archivos.
- **Cómo:** `audeep --serve` (default 8766, evita Koupper 8080).

## 7. Frontend `audeep-web` — "El escaparate bonito"
**Analogía:** La tienda con luces, no el almacén.

- **Qué hace:** `Vite + React + Chart.js` en `5111` lee `8766/json` cada 5s y pinta `4 stats` + `3 charts` (vendors, severidad dona, puertos) + tabla filtrable + drawer al click (detalle CVE con NVD link).
- **Para qué:** Ver todo chido sin abrir `JSON` a mano. Es el `mamón` que querías, pero sin perder el `file://` offline.

## 8. Pi/USB — "El aparato que hace todo solo"
**Analogía:** Dejas una cajita enchufada y te trae el papel.

- **Qué hace:** `Pi` con `systemd` arranca `audeep` al enchufar, escanea, y al meter USB copia `AuDeep_<fecha>/` y parpadea LED. `Docker` `5da82a5` musl 7MB para `x86_64-unknown-linux-musl`.
- **Para qué:** Auditoría en redes sin PC, solo corriente + Ethernet.

---

**En una frase:** AuDeep es *un solo binario Rust 7MB que te dice qué tienes, quién está contigo en la red, qué puertas tienen abiertas y si son peligrosas, y te lo deja bonito en tu browser, sin internet y sin ser experto*.

¿Quieres que añada esta guía como `http://127.0.0.1:5111/docs` tab "Guía Simple" además de la técnica?
