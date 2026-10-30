CREATE TABLE IF NOT EXISTS events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    user   TEXT NOT NULL,
    ip     TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('failed','accepted'))
);

CREATE INDEX IF NOT EXISTS idx_events_ip   ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts);

CREATE VIEW IF NOT EXISTS v_failed_by_ip AS
SELECT ip, COUNT(*) AS failed_count, MIN(ts) AS first_seen, MAX(ts) AS last_seen
FROM events WHERE result='failed' GROUP BY ip ORDER BY failed_count DESC;

CREATE VIEW IF NOT EXISTS v_suspected_bruteforce AS
SELECT ip, user, COUNT(*) AS attempts
FROM events WHERE result='failed' GROUP BY ip, user
HAVING COUNT(*) >= 5 ORDER BY attempts DESC;

CREATE TABLE IF NOT EXISTS http_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    ip     TEXT NOT NULL,
    method TEXT NOT NULL,
    path   TEXT NOT NULL,
    status INTEGER NOT NULL,
    bytes  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_http_ip     ON http_events(ip);
CREATE INDEX IF NOT EXISTS idx_http_status ON http_events(status);
CREATE INDEX IF NOT EXISTS idx_http_ts     ON http_events(ts);

CREATE VIEW IF NOT EXISTS v_scan_and_bruteforce AS
SELECT a.ip,
       a.ssh_fails,
       h.http_404s
FROM (SELECT ip, COUNT(*) AS ssh_fails FROM events
      WHERE result='failed' GROUP BY ip) a
INNER JOIN (SELECT ip, COUNT(*) AS http_404s FROM http_events
            WHERE status=404 GROUP BY ip) h
ON a.ip = h.ip
WHERE a.ssh_fails >= 5 AND h.http_404s >= 5
ORDER BY a.ssh_fails DESC;
