SELECT ip, ts, user FROM events
WHERE result='failed'
  AND CAST(strftime('%H', ts) AS INTEGER) BETWEEN 0 AND 5
ORDER BY ts;
