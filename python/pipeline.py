#!/usr/bin/env python3
import re, sqlite3
from datetime import datetime
from pathlib import Path

PAT = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd\[\d+\]:\s+(?P<res>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)

def main():
    year = str(datetime.now(__import__("datetime").UTC).year)
    rows = []
    for line in Path("data/sample_auth.log").read_text().splitlines():
        m = PAT.match(line)
        if not m:
            continue
        ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S").isoformat()
        rows.append((ts, m["user"], m["ip"], m["res"].lower()))

    Path("data/events.csv").write_text(
        "ts,user,ip,result\n" + "\n".join(",".join(r) for r in rows) + "\n"
    )

    db = Path("data/absolutus.db")
    if db.exists():
        db.unlink()
    con = sqlite3.connect(db)
    con.executescript(Path("sql/schema.sql").read_text())
    con.executemany("INSERT INTO events(ts,user,ip,result) VALUES(?,?,?,?)", rows)
    con.commit()
    con.close()
    print(f"[+] {len(rows)} events -> data/events.csv, data/absolutus.db")

if __name__ == "__main__":
    main()
