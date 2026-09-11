# AuDeep - Actualizar OUI DB completa desde IEEE
param(
  [string]$Out = "assets/oui_full.json"
)
$ErrorActionPreference = "Stop"
$tmp = "$env:TEMP\oui.txt"
Write-Host "Descargando https://standards-oui.ieee.org/oui/oui.txt ..."
curl.exe -L -o $tmp "https://standards-oui.ieee.org/oui/oui.txt"
Write-Host "Parseando ..."
python3 -c @"
import re, json, pathlib
txt = pathlib.Path(r'$tmp').read_text(encoding='utf-8', errors='ignore')
pat = re.compile(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$', re.MULTILINE)
m = pat.findall(txt)
print(f'found {len(m)}')
d = {k.replace('-', ':'): v.strip() for k,v in m}
out = pathlib.Path(r'$Out')
# Si se ejecuta desde scripts/, ajustar ruta
if not out.is_absolute():
    out = pathlib.Path(r'C:\Users\jacob\develop\audeep') / out
out.parent.mkdir(parents=True, exist_ok=True)
with open(out, 'w', encoding='utf-8') as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
print(f'saved {len(d)} to {out} ({out.stat().st_size/1024:.1f}KB)')
"@
Write-Host "Listo: $Out"
