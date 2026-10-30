"""Absolutus_V5 - Streamlit dashboard over the SQLite DB."""
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

DB = Path("data/absolutus.db")

st.set_page_config(page_title="Absolutus_V5", layout="wide")
st.title("Absolutus_V5 — Security Log Dashboard")
st.caption("SSH auth + nginx access → detection views → interactive view.")

if not DB.exists():
    st.error("data/absolutus.db not found. Run `absolutus parse` first.")
    st.stop()

con = sqlite3.connect(DB)
auth = pd.read_sql_query("SELECT * FROM events", con)
http = pd.read_sql_query("SELECT * FROM http_events", con)
corr = pd.read_sql_query("SELECT * FROM v_scan_and_bruteforce", con)
con.close()

for df in (auth, http):
    if not df.empty:
        df["ts"] = pd.to_datetime(df["ts"])

# --- Filters ---
with st.sidebar:
    st.header("Filters")
    ips = sorted(auth["ip"].unique().tolist()) if not auth.empty else []
    ip_sel = st.multiselect("IPs", ips, default=ips)
    users = sorted(auth["user"].unique().tolist()) if not auth.empty else []
    user_sel = st.multiselect("Users", users, default=users)
    result_sel = st.multiselect(
        "Auth result", ["failed", "accepted"], default=["failed", "accepted"]
    )

if not auth.empty:
    mask = (
        auth["ip"].isin(ip_sel)
        & auth["user"].isin(user_sel)
        & auth["result"].isin(result_sel)
    )
    view = auth[mask]
else:
    view = auth

# --- KPIs ---
c1, c2, c3, c4 = st.columns(4)
c1.metric("Auth events", len(auth))
failed_count = int((auth["result"] == "failed").sum()) if not auth.empty else 0
c2.metric("Failed logins", failed_count)
c3.metric("HTTP events", len(http))
c4.metric("High-risk IPs", len(corr))

# --- Charts ---
st.subheader("Failed logins over time")
if not view.empty and (view["result"] == "failed").any():
    ts = (
        view[view["result"] == "failed"]
        .assign(hour=lambda d: d["ts"].dt.floor("h"))
        .groupby("hour")
        .size()
        .rename("count")
    )
    st.bar_chart(ts)
else:
    st.info("No failed logins for the current filter.")

st.subheader("Top IPs by failed attempts")
if not view.empty:
    top = (
        view[view["result"] == "failed"]
        .groupby("ip")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )
    st.bar_chart(top)
else:
    st.info("No data.")

st.subheader("HTTP status distribution")
if not http.empty:
    st.bar_chart(http.groupby("status").size().rename("count"))

# --- Correlation table ---
st.subheader("Scan + brute-force correlation")
if corr.empty:
    st.info("No IPs meet the correlation threshold.")
else:
    st.dataframe(corr, use_container_width=True)

# --- Raw ---
with st.expander("Raw auth events"):
    st.dataframe(view.sort_values("ts", ascending=False), use_container_width=True)
with st.expander("Raw HTTP events"):
    st.dataframe(http, use_container_width=True)
