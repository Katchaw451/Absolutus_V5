"""Absolutus_V5 command-line interface."""
import argparse
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

from absolutus import __version__
from absolutus.parsers import main as parse_main

DB_PATH = Path("data/absolutus.db")
QUERIES_DIR = Path("sql/queries")

RULES = {
    "top": QUERIES_DIR / "01_top_attackers.sql",
    "bruteforce": QUERIES_DIR / "02_bruteforce.sql",
    "offhours": QUERIES_DIR / "03_offhours.sql",
    "correlation": QUERIES_DIR / "04_scan_correlation.sql",
}


def cmd_parse(args):
    """Run the parse pipeline (auth + nginx -> CSV + SQLite)."""
    parse_main()
    return 0


def cmd_detect(args):
    """Run a named detection query against the SQLite DB."""
    if not DB_PATH.exists():
        print("DB not found. Run 'absolutus parse' first.", file=sys.stderr)
        return 1
    sql = RULES[args.rule].read_text()
    con = sqlite3.connect(DB_PATH)
    try:
        for row in con.execute(sql):
            print("|".join("" if v is None else str(v) for v in row))
    finally:
        con.close()
    return 0


def cmd_report(args):
    """Parse then render R Markdown (skipped if Rscript is absent)."""
    parse_main()
    if not shutil.which("Rscript"):
        print("Rscript not found, skipping report.", file=sys.stderr)
        return 0
    subprocess.run(
        ["Rscript", "-e", "rmarkdown::render('r/analysis.Rmd')"],
        check=False,
    )
    return 0


def cmd_dashboard(args):
    """Launch the Streamlit dashboard."""
    if not shutil.which("streamlit"):
        print(
            "streamlit not found. Install with: pip install -e '.[dashboard]'",
            file=sys.stderr,
        )
        return 1
    subprocess.run(
        ["streamlit", "run", str(Path("src/absolutus/dashboard.py"))],
        check=False,
    )
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="absolutus",
        description="Security log pipeline (SSH auth + nginx -> SQL -> R).",
    )
    p.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("parse", help="Parse logs into CSV + SQLite.")
    sp.set_defaults(func=cmd_parse)

    sd = sub.add_parser("detect", help="Run a detection query.")
    sd.add_argument("rule", choices=list(RULES))
    sd.set_defaults(func=cmd_detect)

    sr = sub.add_parser("report", help="Parse then render R Markdown.")
    sr.set_defaults(func=cmd_report)

    sdash = sub.add_parser("dashboard", help="Launch the Streamlit UI.")
    sdash.set_defaults(func=cmd_dashboard)

    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
