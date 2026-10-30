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
