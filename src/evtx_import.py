"""Import Windows Event Log (.evtx) files into the SOC dashboard schema."""
from __future__ import annotations

import os
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd


def _text(parent: ET.Element, path: str, default: str = "") -> str:
    node = parent.find(path, namespaces={"e": "http://schemas.microsoft.com/win/2004/08/events/event"})
    return (node.text or "").strip() if node is not None else default


def parse_event_xml(xml_text: str) -> dict:
    """Parse one Event Viewer XML record into normalized columns."""
    root = ET.fromstring(xml_text)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", ns)
    if system is None:
        raise ValueError("This XML does not contain a Windows Event System section.")

    event_id_text = _text(system, "e:EventID")
    time_node = system.find("e:TimeCreated", ns)
    timestamp = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
    computer = _text(system, "e:Computer", "unknown") or "unknown"

    event_data: dict[str, str] = {}
    data = root.find("e:EventData", ns)
    if data is not None:
        for node in data.findall("e:Data", ns):
            name = node.attrib.get("Name", "")
            if name:
                event_data[name.lower()] = (node.text or "").strip()
    # Some providers use UserData rather than EventData; preserve XML as context.
    account = next((event_data[k] for k in (
        "targetusername", "subjectusername", "username", "accountname", "user"
    ) if event_data.get(k)), "unknown")
    domain = event_data.get("targetdomainname") or event_data.get("subjectdomainname", "")
    if account != "unknown" and domain and domain not in ("-", "") and "\\" not in account:
        account = f"{domain}\\{account}"
    source_ip = next((event_data[k] for k in (
        "ipaddress", "sourceaddress", "sourcenetworkaddress", "clientaddress"
    ) if event_data.get(k)), "unknown")
    if source_ip in ("-", "::1", "127.0.0.1", ""):
        source_ip = "unknown" if source_ip in ("-", "") else source_ip
    logon_type = event_data.get("logontype", "")
    status = event_data.get("status") or event_data.get("substatus", "")
    message = "; ".join(f"{key}={value}" for key, value in event_data.items() if value)

    try:
        event_id = int(event_id_text)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid Windows Event ID: {event_id_text!r}") from exc
    if not timestamp:
        raise ValueError("Windows event is missing its SystemTime timestamp.")

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "computer": computer,
        "account": account,
        "source_ip": source_ip or "unknown",
        "logon_type": logon_type,
        "status": status,
        "message": message or "Windows event record imported from EVTX",
    }


def parse_evtx_bytes(content: bytes) -> pd.DataFrame:
    """Parse bytes from an uploaded .evtx file using python-evtx."""
    if not content:
        raise ValueError("The uploaded EVTX file is empty.")
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        raise RuntimeError("EVTX support is missing. Run: pip install python-evtx") from exc

    temp_path = None
    rows = []
    try:
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as temp:
            temp.write(content)
            temp_path = temp.name
        with Evtx(temp_path) as log:
            for record in log.records():
                try:
                    rows.append(parse_event_xml(record.xml()))
                except (ET.ParseError, ValueError):
                    # A malformed record should not prevent importing the rest of the log.
                    continue
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
    if not rows:
        raise ValueError("No readable Windows events were found in this EVTX file.")
    return pd.DataFrame(rows)
