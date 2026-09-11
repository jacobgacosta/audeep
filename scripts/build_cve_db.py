#!/usr/bin/env python3
"""Genera assets/cve.db SQLite desde assets/vuln_db.json (y futuro NVD feed)."""
import json, sqlite3, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
src = root / "assets" / "vuln_db.json"
dst = root / "assets" / "cve.db"

data = json.loads(src.read_text(encoding="utf-8"))
con = sqlite3.connect(dst)
cur = con.cursor()
cur.execute("DROP TABLE IF EXISTS vulnerabilities")
cur.execute("""
CREATE TABLE vulnerabilities (
  cve TEXT PRIMARY KEY,
  severity TEXT NOT NULL,
  service TEXT NOT NULL,
  affected TEXT NOT NULL,
  description TEXT NOT NULL,
  match_banner_contains TEXT NOT NULL, -- JSON array
  match_ports TEXT NOT NULL,           -- JSON array
  recommendation TEXT NOT NULL
)
""")
cur.execute("DROP TABLE IF EXISTS meta")
cur.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
for e in data:
    cur.execute("INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?)", (
        e["cve"], e["severity"], e["service"], e["affected"], e["description"],
        json.dumps(e.get("match_banner_contains", []), ensure_ascii=False),
        json.dumps(e.get("match_ports", []), ensure_ascii=False),
        e["recommendation"]
    ))
cur.execute("INSERT INTO meta VALUES (?,?)", ("count", str(len(data))))
cur.execute("INSERT INTO meta VALUES (?,?)", ("source", "vuln_db.json"))
con.commit()
# verifica
cur.execute("SELECT count(*) FROM vulnerabilities")
print(f"OK: {dst} -> {cur.fetchone()[0]} vulns")
# indices para query rápida por service/severity
cur.execute("CREATE INDEX IF NOT EXISTS idx_service ON vulnerabilities(service)")
cur.execute("CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)")
con.commit()
con.close()
