import pandas as pd

REQUIRED_COLUMNS = ["timestamp", "event_id"]

def normalize_events(frame):
    if frame is None or frame.empty:
        return pd.DataFrame(columns=["timestamp","event_id","computer","account","source_ip","logon_type","status","message"])
    df = frame.copy()
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError("CSV is missing required column(s): " + ", ".join(missing))
    defaults = {"computer":"unknown","account":"unknown","source_ip":"unknown","logon_type":"","status":"","message":""}
    for col, default in defaults.items():
        if col not in df.columns: df[col] = default
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce")
    df = df.dropna(subset=["timestamp","event_id"]).copy()
    df["event_id"] = df["event_id"].astype(int)
    for col in ["computer","account","source_ip","logon_type","status","message"]:
        df[col] = df[col].fillna("").astype(str).str.strip()
    for col in ["computer","account","source_ip"]:
        df[col] = df[col].replace("", "unknown")
    return df.sort_values("timestamp").reset_index(drop=True)
