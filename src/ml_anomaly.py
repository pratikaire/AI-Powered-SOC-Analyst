"""Unsupervised anomaly scoring for event-level security logs."""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

FEATURE_COLUMNS = ["event_id", "hour_utc", "day_of_week", "is_failed_logon",
                   "is_success_logon", "is_privileged_event", "account_failure_count",
                   "source_failure_count", "distinct_accounts_per_source"]

def build_features(events):
    """Build numeric features from normalized event rows without using raw names/IPs."""
    if events is None or events.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS)
    df = events.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce")
    df = df.dropna(subset=["timestamp","event_id"]).copy()
    df["event_id"] = df["event_id"].astype(int)
    df["account"] = df.get("account", "unknown").fillna("unknown").astype(str)
    df["source_ip"] = df.get("source_ip", "unknown").fillna("unknown").astype(str)
    df = df.sort_values("timestamp")
    df["hour_utc"] = df.timestamp.dt.hour
    df["day_of_week"] = df.timestamp.dt.dayofweek
    df["is_failed_logon"] = (df.event_id == 4625).astype(int)
    df["is_success_logon"] = (df.event_id == 4624).astype(int)
    df["is_privileged_event"] = (df.event_id == 4672).astype(int)
    failed = df.event_id == 4625
    df["account_failure_count"] = failed.groupby(df.account).transform("sum")
    df["source_failure_count"] = failed.groupby(df.source_ip).transform("sum")
    df["distinct_accounts_per_source"] = df.groupby("source_ip").account.transform("nunique")
    return df[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan).fillna(0)

def score_anomalies(events, contamination=0.15, random_state=42):
    """Fit Isolation Forest on the supplied batch and return anomaly score/flag.

    This is an unsupervised baseline, not a trained production detector. The model
    needs a representative dataset; synthetic sample results are for demonstration.
    """
    features = build_features(events)
    if len(features) < 5:
        raise ValueError("At least 5 valid events are required for anomaly scoring.")
    model = make_pipeline(
        StandardScaler(),
        IsolationForest(contamination=float(contamination), random_state=random_state, n_estimators=150)
    )
    model.fit(features)
    raw_prediction = model.predict(features)  # -1 = anomaly, 1 = inlier
    decision = model.decision_function(features)  # lower = more anomalous
    result = events.loc[features.index].copy().reset_index(drop=True)
    anomaly_flags = (raw_prediction == -1)
    # Defensive fallback for edge cases where this fitted model flags no rows.
    # The top-ranked events remain triage candidates, not confirmed attacks.
    if not anomaly_flags.any():
        count = max(1, int(np.ceil(float(contamination) * len(features))))
        anomaly_flags[np.argsort(decision)[:count]] = True
    result["anomaly_flag"] = anomaly_flags
    result["anomaly_score"] = (-decision).round(5)
    result["ml_reason"] = result.apply(
        lambda row: "Flagged as unusual relative to this imported batch; investigate the event."
        if row["anomaly_flag"] else "Not flagged as unusual relative to this imported batch.", axis=1
    )
    return result.sort_values("anomaly_score", ascending=False).reset_index(drop=True)
