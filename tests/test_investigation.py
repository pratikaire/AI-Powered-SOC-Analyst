import pandas as pd
from src.investigation import build_investigation

def test_rule_alert_returns_checks_and_limitations():
    result = build_investigation({
        "rule": "Repeated failed logons", "timestamp": "2026-10-10T09:05:00+00:00",
        "account": "demo-user", "source_ip": "192.0.2.55", "severity": "Medium", "count": 5
    })
    assert result["checks"]
    assert result["recommended_actions"]
    assert "not a verdict" in result["limitations"]
    assert any("demo-user" in item for item in result["evidence"])

def test_ml_anomaly_includes_score_and_caveat():
    result = build_investigation({
        "timestamp": "2026-10-10T09:05:00+00:00", "event_id": 4625,
        "account": "demo-user", "source_ip": "192.0.2.55", "anomaly_flag": True,
        "anomaly_score": 0.12345
    }, source="ML anomaly")
    assert any("0.12345" in item for item in result["evidence"])
    assert "not a probability" in " ".join(result["evidence"])
    assert result["checks"]

def test_unknown_rule_uses_generic_playbook():
    result = build_investigation({"rule": "Something new"})
    assert result["checks"]
    assert result["recommended_actions"]
