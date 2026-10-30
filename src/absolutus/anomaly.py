"""Absolutus_V5 - unsupervised anomaly detection over per-IP behavior."""
import sqlite3
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest

DB = Path("data/absolutus.db")


def load_features(db_path: Path = DB) -> pd.DataFrame:
    """Build per-IP behavior features from the SQLite events tables."""
    con = sqlite3.connect(db_path)
    auth = pd.read_sql_query("SELECT * FROM events", con)
    http = pd.read_sql_query("SELECT * FROM http_events", con)
    con.close()

    for df in (auth, http):
        if not df.empty:
            df["ts"] = (
                pd.to_datetime(df["ts"], utc=True)
                .dt.tz_localize(None)
            )

    ips = set(auth["ip"]).union(set(http["ip"]))
    rows = []
    for ip in ips:
        a = auth[auth["ip"] == ip] if not auth.empty else auth
        h = http[http["ip"] == ip] if not http.empty else http
        if a.empty and h.empty:
            all_ts = pd.Series(dtype="datetime64[ns]")
        else:
            all_ts = pd.concat([a["ts"], h["ts"]])

        n_auth = len(a)
        n_http = len(h)
        n_failed = int((a["result"] == "failed").sum()) if n_auth else 0
        n_404 = int((h["status"] == 404).sum()) if n_http else 0
        n_unique_users = a["user"].nunique() if n_auth else 0

        if len(all_ts) >= 2:
            span_min = max((all_ts.max() - all_ts.min()).total_seconds() / 60.0, 1.0)
        else:
            span_min = 1.0

        rate_per_min = (n_auth + n_http) / span_min
        offhours = int(((all_ts.dt.hour < 6) | (all_ts.dt.hour >= 22)).sum())
        offhours_ratio = offhours / max(len(all_ts), 1)
        http_404_ratio = n_404 / n_http if n_http else 0.0

        rows.append({
            "ip": ip,
            "n_events": n_auth + n_http,
            "n_failed_auth": n_failed,
            "n_http_404": n_404,
            "unique_users": n_unique_users,
            "rate_per_min": rate_per_min,
            "offhours_ratio": offhours_ratio,
            "http_404_ratio": http_404_ratio,
        })
    return pd.DataFrame(rows)


def score(df: pd.DataFrame, random_state: int = 42) -> pd.DataFrame:
    """Run IsolationForest and return the dataframe with anomaly_score."""
    feature_cols = [
        "n_events", "n_failed_auth", "n_http_404", "unique_users",
        "rate_per_min", "offhours_ratio", "http_404_ratio",
    ]
    X = df[feature_cols].fillna(0.0).to_numpy(dtype=float)
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=random_state,
    )
    model.fit(X)
    # score_samples: lower = more anomalous; flip and normalize to [0,1]
    raw = -model.score_samples(X)
    df = df.copy()
    df["anomaly_score"] = (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)
    df["is_anomaly"] = model.predict(X) == -1
    return df.sort_values("anomaly_score", ascending=False).reset_index(drop=True)


def persist(df: pd.DataFrame, db_path: Path = DB) -> None:
    """Write anomaly scores to the anomaly_scores table."""
    con = sqlite3.connect(db_path)
    con.execute("DROP TABLE IF EXISTS anomaly_scores")
    con.execute("""
        CREATE TABLE anomaly_scores (
            ip             TEXT PRIMARY KEY,
            anomaly_score  REAL,
            is_anomaly     INTEGER,
            n_events       INTEGER,
            n_failed_auth  INTEGER,
            n_http_404     INTEGER
        )
    """)
    con.executemany(
        "INSERT INTO anomaly_scores VALUES (?,?,?,?,?,?)",
        df[[
            "ip", "anomaly_score", "is_anomaly",
            "n_events", "n_failed_auth", "n_http_404",
        ]].itertuples(index=False, name=None),
    )
    con.commit()
    con.close()


def run(db_path: Path = DB) -> pd.DataFrame:
    """End-to-end: load features -> score -> persist -> return ranked df."""
    df = load_features(db_path)
    scored = score(df)
    persist(scored, db_path)
    return scored


if __name__ == "__main__":
    ranked = run()
    top = ranked.head(10)[["ip", "anomaly_score", "is_anomaly", "n_events"]]
    print(top.to_string(index=False))
