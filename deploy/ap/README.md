# AuDeep AP Mode

Modo Access Point para cuando la Pi no tiene Ethernet o la red está aislada.

## Qué hace
- Crea WiFi `AuDeep-Auditor` (pass `audeep2026`) en `wlan0` con `192.168.4.1/24`
- `dnsmasq` da DHCP `192.168.4.2-20` + DNS + portal cautivo `/#/192.168.4.1`
- `audeep --serve 192.168.4.1:80` expone reporte en vivo (HTML)

## Instalación
```bash
sudo apt update && sudo apt install -y hostapd dnsmasq
sudo cp deploy/ap/hostapd.conf /etc/hostapd/hostapd.conf
sudo cp deploy/ap/dnsmasq.conf /etc/dnsmasq.d/audeep.conf
sudo cp deploy/ap/setup_ap.sh /usr/local/bin/audeep-ap && sudo chmod +x /usr/local/bin/audeep-ap
# Activa
sudo audeep-ap on
# Ver
sudo audeep-ap status
# Desactiva (vuelve a WiFi cliente)
sudo audeep-ap off
```

## Flujo usuario no técnico
1. Conecta Pi a corriente (sin Ethernet).
2. Si a los 60s no hay `eth0` con IP, `audeep.service` puede llamar `audeep-ap on` automáticamente (opcional: `ExecStartPre=/usr/local/bin/audeep-ap on`).
3. En tu móvil busca WiFi `AuDeep-Auditor`, pass `audeep2026`.
4. Abre `http://192.168.4.1` — ves hardware + hosts + vulns en vivo.
5. Inserta USB → `audeep-usb.sh` copia también el reporte AP.

## Seguridad
- Cambia `wpa_passphrase` en `hostapd.conf`.
- Para AP abierto de auditoría rápida: comenta `wpa=` lineas.
- No hace NAT por defecto a `eth0` si no hay internet, es AP aislado (solo para auditoría).
