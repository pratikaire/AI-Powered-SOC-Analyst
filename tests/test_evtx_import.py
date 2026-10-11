from src.evtx_import import parse_event_xml


def test_parse_event_xml_extracts_windows_security_fields():
    xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4625</EventID>
        <TimeCreated SystemTime="2026-10-11T04:00:00.000Z" />
        <Computer>WORKSTATION-01</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">demo-user</Data>
        <Data Name="TargetDomainName">WORKGROUP</Data>
        <Data Name="IpAddress">192.0.2.55</Data>
        <Data Name="LogonType">3</Data>
        <Data Name="Status">0xC000006D</Data>
      </EventData>
    </Event>'''
    row = parse_event_xml(xml)
    assert row["event_id"] == 4625
    assert row["account"] == "WORKGROUP\\demo-user"
    assert row["source_ip"] == "192.0.2.55"
    assert row["logon_type"] == "3"
    assert row["computer"] == "WORKSTATION-01"


def test_parse_event_xml_rejects_missing_timestamp():
    xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>4624</EventID><Computer>PC</Computer></System>
    </Event>'''
    try:
        parse_event_xml(xml)
    except ValueError as exc:
        assert "timestamp" in str(exc).lower()
    else:
        raise AssertionError("Expected missing timestamp to raise ValueError")
