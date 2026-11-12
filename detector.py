"""Detection engine: per-source time-window features + rule-based and ML detection."""
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ["packets", "bytes", "unique_ports", "unique_dsts", "syn_count", "syn_ratio", "avg_len"]


def load_packets(path):
    df = pd.read_csv(path)
    df["flags"] = df["flags"].fillna("").astype(str)
    df["dt"] = pd.to_datetime(df["ts"], unit="s")
    df["is_syn"] = (df["flags"] == "S").astype(int)  # SYN without ACK
    return df


def window_features(df, window="10s"):
    df = df.copy()
    df["window"] = df["dt"].dt.floor(window)
    feats = (
        df.groupby(["window", "src"])
        .agg(
            packets=("length", "size"),
            bytes=("length", "sum"),
            unique_ports=("dport", "nunique"),
            unique_dsts=("dst", "nunique"),
            syn_count=("is_syn", "sum"),
            avg_len=("length", "mean"),
        )
        .reset_index()
    )
    feats["syn_ratio"] = feats["syn_count"] / feats["packets"]
    return feats


def rule_alerts(feats, port_thresh=20, syn_thresh=200):
    alerts = []
    for _, r in feats.iterrows():
        if r.unique_ports >= port_thresh and r.syn_ratio > 0.8:
            alerts.append(dict(time=r.window, src=r.src, type="Port scan", severity="High",
                               detail=f"{r.unique_ports} distinct ports probed in window"))
        if r.syn_count >= syn_thresh and r.syn_ratio > 0.8:
            alerts.append(dict(time=r.window, src=r.src, type="SYN flood", severity="Critical",
                               detail=f"{int(r.syn_count)} SYN packets in window"))
    return alerts


def ml_alerts(feats, contamination=0.01):
    if len(feats) < 30:
        return []
    X = StandardScaler().fit_transform(feats[FEATURES])
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    pred = model.fit_predict(X)
    score = -model.decision_function(X)
    out = []
    for i in (pred == -1).nonzero()[0]:
        r = feats.iloc[i]
        out.append(dict(time=r.window, src=r.src, type="ML anomaly", severity="Medium",
                        detail=f"anomaly score {score[i]:.2f} ({int(r.packets)} pkts, {int(r.bytes)} bytes)"))
    return out


def detect(df, window="10s", port_thresh=20, syn_thresh=200, contamination=0.01):
    feats = window_features(df, window)
    alerts = rule_alerts(feats, port_thresh, syn_thresh) + ml_alerts(feats, contamination)
    cols = ["time", "src", "type", "severity", "detail"]
    alerts_df = pd.DataFrame(alerts, columns=cols)
    if not alerts_df.empty:
        alerts_df = alerts_df.sort_values("time", ascending=False).reset_index(drop=True)
    return feats, alerts_df
