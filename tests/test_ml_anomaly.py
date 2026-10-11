import pandas as pd
from src.preprocessing import normalize_events
from src.ml_anomaly import build_features, score_anomalies

def sample_events():
    rows=[]
    for i in range(12):
        rows.append({"timestamp":f"2026-10-10T09:{i:02d}:00Z","event_id":4624 if i%3 else 4625,
                     "account":f"user{i%4}","source_ip":f"192.0.2.{i%3+1}","computer":"TEST-PC"})
    return normalize_events(pd.DataFrame(rows))

def test_feature_builder_returns_numeric_rows():
    events=sample_events(); features=build_features(events)
    assert len(features)==len(events)
    assert all(pd.api.types.is_numeric_dtype(features[c]) for c in features.columns)

def test_isolation_forest_returns_flags_and_scores():
    result=score_anomalies(sample_events(),contamination=0.15)
    assert len(result)==12
    assert "anomaly_flag" in result
    assert result["anomaly_flag"].any()
    assert result["anomaly_score"].notna().all()

def test_too_few_events_is_clear_error():
    events=sample_events().head(4)
    try: score_anomalies(events)
    except ValueError as exc: assert "At least 5" in str(exc)
    else: raise AssertionError("Expected ValueError")
