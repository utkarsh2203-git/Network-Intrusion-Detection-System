"""Streamlit dashboard.   Run:  streamlit run dashboard.py"""
import os, time
import pandas as pd
import streamlit as st
from detector import load_packets, detect

st.set_page_config(page_title="NIDS Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ Network Intrusion Detection System")

# ---- Sidebar controls ----
st.sidebar.header("Settings")
source = st.sidebar.radio("Data source", ["Sample data", "Live capture (data/packets.csv)", "Upload CSV"])
window = st.sidebar.selectbox("Analysis window", ["5s", "10s", "30s", "60s"], index=1)
port_thresh = st.sidebar.slider("Port-scan threshold (distinct ports)", 5, 100, 20)
syn_thresh = st.sidebar.slider("SYN-flood threshold (SYNs/window)", 50, 1000, 200, step=50)
contamination = st.sidebar.slider("ML anomaly sensitivity", 0.001, 0.10, 0.01, format="%.3f")
auto = st.sidebar.checkbox("Auto-refresh (5s)", value=False)

# ---- Load data ----
path = None
if source == "Sample data":
    path = "data/sample_packets.csv"
elif source.startswith("Live"):
    path = "data/packets.csv"
else:
    up = st.sidebar.file_uploader("CSV with columns: ts,src,dst,sport,dport,proto,length,flags")
    if up:
        path = up

if path is None or (isinstance(path, str) and not os.path.exists(path)):
    st.warning("No data found. Run `python generate_sample_data.py` or `python capture.py` first.")
    st.stop()

df = load_packets(path)
if df.empty:
    st.info("Capture file is empty so far.")
    st.stop()

feats, alerts = detect(df, window, port_thresh, syn_thresh, contamination)

# ---- KPIs ----
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total packets", f"{len(df):,}")
c2.metric("Unique sources", df["src"].nunique())
c3.metric("Total traffic", f"{df['length'].sum() / 1e6:.2f} MB")
c4.metric("Alerts", len(alerts))

# ---- Traffic over time ----
st.subheader("Traffic over time")
ts = df.set_index("dt").resample(window).agg(packets=("length", "size"), syn=("is_syn", "sum"))
st.line_chart(ts)

left, right = st.columns(2)
with left:
    st.subheader("Protocol distribution")
    st.bar_chart(df["proto"].value_counts())
with right:
    st.subheader("Top talkers (by packets)")
    st.bar_chart(df["src"].value_counts().head(10))

# ---- Alerts ----
st.subheader("🚨 Alerts")
if alerts.empty:
    st.success("No suspicious activity detected.")
else:
    types = st.multiselect("Filter by type", alerts["type"].unique(), default=list(alerts["type"].unique()))
    st.dataframe(alerts[alerts["type"].isin(types)], use_container_width=True)
    st.caption("Rule-based: port scan, SYN flood. ML-based: Isolation Forest on per-source window features.")

with st.expander("Per-source window features"):
    st.dataframe(feats, use_container_width=True)

if auto:
    time.sleep(5)
    st.rerun()
