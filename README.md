# Absolutus_V5

Cybersecurity + data portfolio: raw auth logs → Python → SQL → R.

**Stack:** Python · SQL · R · Cybersecurity

## Pipeline
data/sample_auth.log
│ python/pipeline.py
▼
data/events.csv + data/absolutus.db (SQLite)
│ sql/schema.sql + sql/queries/*
▼
detection views → r/analysis.Rmd → HTML report


## Run
make run # parse log → SQLite + CSV
make report # render R Markdown (needs R)

## License
MIT
