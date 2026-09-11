#!/bin/bash
# AuDeep - Build para Raspberry Pi (Linux host)
set -e
for T in aarch64-unknown-linux-gnu armv7-unknown-linux-gnueabihf x86_64-unknown-linux-musl; do
  echo "=== target $T ==="
  rustup target add $T
  cargo zigbuild --target $T --release
  ls -lh target/$T/release/audeep*
done
echo "Listo. Copiar con: scp target/aarch64-unknown-linux-gnu/release/audeep pi@raspberrypi:/tmp/"
