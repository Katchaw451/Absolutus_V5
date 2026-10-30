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
