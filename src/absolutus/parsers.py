#!/usr/bin/env python3
"""Absolutus_V5 - parse SSH auth + nginx access logs into SQLite."""
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

AUTH_PAT = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd\[\d+\]:\s+(?P<res>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)

NGINX_PAT = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)'
)


def parse_auth(path, year):
    rows = []
    for line in Path(path).read_text().splitlines():
        m = AUTH_PAT.match(line)
        if not m:
            continue
        ts = datetime.strptime(
            f"{year} {m['ts']}", "%Y %b %d %H:%M:%S"
        ).isoformat()
        rows.append((ts, m["user"], m["ip"], m["res"].lower()))
    return rows


def parse_nginx(path):
    rows = []
    for line in Path(path).read_text().splitlines():
        m = NGINX_PAT.match(line)
        if not m:
            continue
        ts = datetime.strptime(
            m["ts"], "%d/%b/%Y:%H:%M:%S %z"
        ).isoformat()
        b = None if m["bytes"] == "-" else int(m["bytes"])
        rows.append((ts, m["ip"], m["method"], m["path"],
                     int(m["status"]), b))
    return rows


def main(auth=None, nginx=None):
    year = str(datetime.now(timezone.utc).year)
    auth_p = Path(auth) if auth else Path("data/sample_auth.log")
    nginx_p = Path(nginx) if nginx else Path("data/sample_nginx.log")
    auth = parse_auth(auth_p, year) if auth_p.exists() else []
    http = parse_nginx(nginx_p) if nginx_p.exists() else []

    db = Path("data/absolutus.db")
    if db.exists():
        db.unlink()
    con = sqlite3.connect(db)
    con.executescript(Path("sql/schema.sql").read_text())
    con.executemany(
        "INSERT INTO events(ts,user,ip,result) VALUES(?,?,?,?)", auth
    )
    con.executemany(
        "INSERT INTO http_events(ts,ip,method,path,status,bytes) "
        "VALUES(?,?,?,?,?,?)", http
    )
    con.commit()
    con.close()

    Path("data/events.csv").write_text(
        "ts,user,ip,result\n" + "\n".join(",".join(r) for r in auth) + "\n"
    )
    print(f"[+] {len(auth)} auth events, {len(http)} http events -> data/")


if __name__ == "__main__":
    main()
