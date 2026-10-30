# Changelog

## [v1.0.0] - 2026-10-30

### Added
- Python SSH auth log parser (python/pipeline.py).
- SQLite schema with events table and views v_failed_by_ip and v_suspected_bruteforce.
- Detection queries: top attackers, brute-force, off-hours.
- R Markdown report with time-series and per-IP plots.
- Unit tests for the parser (tests/test_pipeline.py).
- Makefile targets: run, test, report, clean.
- Sample dataset and security detection notes.

## [v2.0.0] - 2026-10-30

### Added
- Nginx access log parser (http_events table).
- Correlation view v_scan_and_bruteforce (SSH fails + HTTP 404 scanning).
- Query 04_scan_correlation.sql.
- Nginx parser unit tests.

### Changed
- pipeline.py handles both sources in a single run.

## [v3.0.0] - 2026-10-30

### Added
- GitHub Actions CI workflow (.github/workflows/ci.yml).
- ruff lint config (pyproject.toml).
- CI badge on README.
- make lint target.
