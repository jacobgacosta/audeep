# AuDeep - Build para Raspberry Pi (Windows host con zig)
# Requiere: zig 0.16 + cargo-zigbuild

$ErrorActionPreference = "Stop"
$zigDir = "C:\Users\jacob\AppData\Local\Temp\zig-x86_64-windows-0.16.0"
if (Test-Path $zigDir) { $env:PATH = "$zigDir;" + $env:PATH }

$targets = @(
  "aarch64-unknown-linux-gnu",      # Pi 3/4/5 64-bit (recomendado)
  "armv7-unknown-linux-gnueabihf",  # Pi 2/3 32-bit
  "x86_64-unknown-linux-musl"       # USB portable Linux estático
)

foreach ($t in $targets) {
  Write-Host "`n=== Instalando target $t ===" -ForegroundColor Cyan
  & "$HOME\.cargo\bin\rustup.exe" target add $t
  Write-Host "=== Compilando $t ===" -ForegroundColor Green
  & "$HOME\.cargo\bin\cargo-zigbuild.exe" zigbuild --target $t --release
  if ($LASTEXITCODE -ne 0) { Write-Error "Fallo $t"; exit 1 }
  $bin = "target\$t\release\audeep"
  if (Test-Path "$bin.exe") { $bin = "$bin.exe" }
  Write-Host "OK: $bin -> $(Get-Item $bin | Select-Object -Expand Length) bytes" -ForegroundColor Green
}

Write-Host "`nTodos los binarios listos en target/*/release/audeep" -ForegroundColor Green
Write-Host "Para desplegar en Pi: scp target/aarch64-unknown-linux-gnu/release/audeep pi@raspberrypi:/tmp/ && ssh pi@raspberrypi 'sudo mv /tmp/audeep /usr/local/bin/ && sudo systemctl daemon-reload && sudo systemctl enable --now audeep'"
