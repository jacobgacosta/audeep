#!/bin/bash
# AuDeep - Setup AP mode en Raspberry Pi
# Uso: sudo bash deploy/ap/setup_ap.sh [on|off|status]
set -e
MODE=${1:-on}
AP_IP="192.168.4.1"
WLAN="wlan0"

log() { echo "[audeep-ap] $*"; }

case "$MODE" in
  on)
    log "Activando AP AuDeep-Auditor..."
    # Detener servicios que interfieren
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl stop hostapd 2>/dev/null || true

    # Configurar IP estática para AP
    ip link set $WLAN down || true
    ip addr flush dev $WLAN || true
    ip addr add $AP_IP/24 dev $WLAN
    ip link set $WLAN up

    # Habilitar forwarding y NAT si hay eth0 con internet (opcional)
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
    iptables -A FORWARD -i $WLAN -o eth0 -j ACCEPT 2>/dev/null || true

    # Configurar dhcp/dns
    cp deploy/ap/dnsmasq.conf /etc/dnsmasq.d/audeep.conf 2>/dev/null || cp dnsmasq.conf /etc/dnsmasq.d/audeep.conf
    cp deploy/ap/hostapd.conf /etc/hostapd/hostapd.conf 2>/dev/null || cp hostapd.conf /etc/hostapd/hostapd.conf
    echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' > /etc/default/hostapd 2>/dev/null || true

    systemctl start dnsmasq
    systemctl start hostapd

    # Iniciar audeep en modo web para AP (puerto 80)
    systemctl restart audeep 2>/dev/null || /usr/local/bin/audeep --serve 192.168.4.1:80 &

    log "AP activo: SSID AuDeep-Auditor / pass audeep2026 / http://192.168.4.1"
    log "Conecta tu móvil/laptop al WiFi y abre http://192.168.4.1 para ver reporte en vivo"
    ;;
  off)
    log "Desactivando AP..."
    systemctl stop hostapd 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true
    ip addr flush dev $WLAN || true
    # Restaurar DHCP cliente
    dhclient $WLAN 2>/dev/null || systemctl restart dhcpcd 2>/dev/null || NetworkManager --print-config 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    log "AP desactivado, vuelves a modo cliente"
    ;;
  status)
    echo "=== hostapd ==="; systemctl status hostapd --no-pager 2>&1 | head -n 20
    echo "=== dnsmasq ==="; systemctl status dnsmasq --no-pager 2>&1 | head -n 20
    echo "=== wlan0 ==="; ip addr show $WLAN 2>&1 | head -n 20
    echo "=== audeep ==="; systemctl status audeep --no-pager 2>&1 | head -n 20
    ;;
  *)
    echo "Uso: $0 [on|off|status]"
    exit 1
    ;;
esac
