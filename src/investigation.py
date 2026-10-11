"""No-API investigation playbooks for common SOC alerts.

This is a transparent, local assistant: it creates triage guidance from alert fields
and does not call an external LLM or claim that an alert proves malicious activity.
"""
from __future__ import annotations
import pandas as pd

PLAYBOOKS = {
    "Repeated failed logons": {
        "why": "Several failed sign-in attempts were observed for the same account and source.",
        "checks": [
            "Confirm whether the account owner recognizes the activity and time window.",
            "Compare the source address with approved VPN, office, and known service addresses.",
            "Review nearby successful logons (Event ID 4624) and the logon type.",
            "Check whether failures continue or affect other accounts.",
        ],
        "actions": [
            "If activity is unexpected, follow your organization's account-protection procedure.",
            "Preserve relevant event records and escalate according to the SOC playbook.",
        ],
    },
    "Possible password spraying": {
        "why": "A single source appears to have attempted sign-ins against multiple accounts.",
        "checks": [
            "Verify the number of distinct accounts and the time range in the raw events.",
            "Check whether the source is a known identity provider, proxy, VPN, or scanner.",
            "Look for successful logons after failures and review affected accounts.",
            "Check identity-provider or endpoint telemetry for corroborating evidence.",
        ],
        "actions": [
            "Escalate if the activity is unfamiliar or accompanied by successful sign-ins.",
            "Follow approved incident-response procedures before blocking an address or disabling accounts.",
        ],
    },
    "Multiple sources targeting one account": {
        "why": "Failed sign-ins for one account were observed from several source addresses.",
        "checks": [
            "Determine whether the addresses map to approved VPN egress or shared networks.",
            "Ask the account owner to verify recent sign-in activity when appropriate.",
            "Correlate timestamps, logon types, device names, and successful logons.",
        ],
        "actions": [
            "Escalate if sources are unrecognized or a suspicious successful logon follows.",
            "Preserve evidence and use approved account-protection procedures.",
        ],
    },
    "Success after repeated failures": {
        "why": "A successful sign-in followed multiple recent failures for the same account and source.",
        "checks": [
            "Verify the successful logon's timestamp, device, source, and logon type.",
            "Confirm with the user or service owner whether the sign-in was expected.",
            "Review the account's subsequent activity and any privilege-related events.",
        ],
        "actions": [
            "Prioritize review when the successful sign-in is unfamiliar or outside normal patterns.",
            "Escalate using the organization's incident-response process if compromise is plausible.",
        ],
    },
    "Privileged logon requires review": {
        "why": "Event ID 4672 indicates special privileges were assigned to a new logon; this can be legitimate.",
        "checks": [
            "Verify that the account is expected to receive special privileges.",
            "Check the device, logon type, timestamp, and nearby authentication events.",
            "Correlate with change tickets or approved administrator activity if available.",
        ],
        "actions": [
            "Document why the privileged activity is expected, or escalate if it cannot be explained.",
        ],
    },
}

DEFAULT_PLAYBOOK = {
    "why": "The event was flagged as unusual by a batch-relative anomaly score.",
    "checks": [
        "Inspect the raw event message and validate the timestamp and event ID.",
        "Compare the account, source, device, and logon type with known normal activity.",
        "Review adjacent events before and after this event for context.",
        "Check independent endpoint, identity, or network evidence if available.",
    ],
    "actions": [
        "Treat the anomaly as a triage lead, not proof of an attack.",
        "Escalate only when the evidence and your organization's process support it.",
    ],
}

def _clean(value, fallback="unknown"):
    if value is None or pd.isna(value) or not str(value).strip():
        return fallback
    return str(value).strip()

def build_investigation(alert: dict | pd.Series, source="rule alert") -> dict:
    """Return a structured, explainable investigation plan for a rule or ML finding."""
    row = dict(alert)
    rule = _clean(row.get("rule"), "Unusual event")
    is_ml = source.lower().startswith("ml") or "anomaly_flag" in row
    playbook = PLAYBOOKS.get(rule, DEFAULT_PLAYBOOK)
    timestamp = _clean(row.get("timestamp"))
    account = _clean(row.get("account"))
    source_ip = _clean(row.get("source_ip"))
    event_id = _clean(row.get("event_id"))
    severity = _clean(row.get("severity"), "Informational")
    count = _clean(row.get("count"), "not supplied")
    score = row.get("anomaly_score")
    if score is not None and not pd.isna(score):
        score_text = f"{float(score):.5f} (relative score; not a probability)"
    else:
        score_text = "not available"
    evidence = [
        f"Finding type: {'ML anomaly' if is_ml else 'Rule-based alert'}",
        f"Rule/event: {rule}" + (f" / Event ID {event_id}" if event_id != "unknown" else ""),
        f"Timestamp: {timestamp}",
        f"Account: {account}",
        f"Source: {source_ip}",
        f"Severity: {severity}",
        f"Event/count value: {count}",
    ]
    if is_ml:
        evidence.append(f"Anomaly score: {score_text}")
    return {
        "title": f"Investigation guide: {rule}",
        "source": source,
        "why_flagged": playbook["why"],
        "evidence": evidence,
        "checks": list(playbook["checks"]),
        "recommended_actions": list(playbook["actions"]),
        "limitations": "This guide is generated locally from available fields and predefined playbooks. It is not a verdict, does not query threat intelligence, and may lack context. Verify every finding against raw logs and authorized telemetry.",
    }
