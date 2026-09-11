#!/bin/bash
# AuDeep - Script de copia automática a USB
# Instalación: sudo cp deploy/usb/audeep-usb.sh /usr/local/bin/ && sudo chmod +x /usr/local/bin/audeep-usb.sh
# Udev lo llama como: audeep-usb.sh sda1
set -e

DEV_NAME=$1
DEV_PATH="/dev/${DEV_NAME}"
MOUNT_POINT="/mnt/audeep_usb"
REPORT_SRC="/var/lib/audeep"
LOG_TAG="audeep-usb"

log() { logger -t "$LOG_TAG" "$*"; echo "[$LOG_TAG] $*"; }

if [ -z "$DEV_NAME" ]; then
  log "Sin dispositivo, saliendo"
  exit 0
fi

# Esperar a que el dispositivo esté listo
sleep 1
if [ ! -b "$DEV_PATH" ]; then
  log "Dispositivo $DEV_PATH no es bloque, saliendo"
  exit 0
fi

# Detectar si ya está montado
if mountpoint -q "$MOUNT_POINT"; then
  log "$MOUNT_POINT ya montado, desmontando previo"
  umount "$MOUNT_POINT" || true
fi

mkdir -p "$MOUNT_POINT"
mkdir -p "$REPORT_SRC"

# Intentar montar (auto-detect FS)
if ! mount "$DEV_PATH" "$MOUNT_POINT" 2>/dev/null; then
  # fallback vfat/exfat/ntfs
  mount -t auto "$DEV_PATH" "$MOUNT_POINT" || {
    log "Fallo montando $DEV_PATH"
    exit 1
  }
fi

log "USB $DEV_PATH montado en $MOUNT_POINT"

# Si no hay reporte, generarlo al vuelo
if [ ! -f "$REPORT_SRC/audeep_reporte.html" ]; then
  log "Reporte no existe, ejecutando audeep rápido"
  /usr/local/bin/audeep --json="$REPORT_SRC/audeep_reporte.json" --html="$REPORT_SRC/audeep_reporte.html" || true
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEST_DIR="$MOUNT_POINT/AuDeep_${TIMESTAMP}"
mkdir -p "$DEST_DIR"

cp -v "$REPORT_SRC/audeep_reporte.json" "$DEST_DIR/" 2>/dev/null || log "JSON no copiado"
cp -v "$REPORT_SRC/audeep_reporte.html" "$DEST_DIR/" 2>/dev/null || log "HTML no copiado"

# También copiar a raíz del USB para acceso rápido
cp -v "$REPORT_SRC/audeep_reporte.html" "$MOUNT_POINT/AuDeep_reporte.html" 2>/dev/null || true

sync
log "Reportes copiados a $DEST_DIR y $MOUNT_POINT/AuDeep_reporte.html"

# Parpadeo LED éxito (3 parpadeos largos)
for i in 1 2 3; do
  echo 1 > /sys/class/leds/led0/brightness 2>/dev/null || true
  echo 1 > /sys/class/leds/ACT/brightness 2>/dev/null || true
  sleep 0.5
  echo 0 > /sys/class/leds/led0/brightness 2>/dev/null || true
  echo 0 > /sys/class/leds/ACT/brightness 2>/dev/null || true
  sleep 0.5
done || true

# Desmontar seguro
sleep 1
umount "$MOUNT_POINT" || log "Advertencia: no se pudo desmontar $MOUNT_POINT"
log "USB listo para retirar"

# 5 parpadeos rápidos = listo
for i in 1 2 3 4 5; do
  echo 1 > /sys/class/leds/led0/brightness 2>/dev/null || true
  sleep 0.15
  echo 0 > /sys/class/leds/led0/brightness 2>/dev/null || true
  sleep 0.15
done || true

exit 0
