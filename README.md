# AI-Powered SOC Analyst — Phase 5

Phase 5 adds an **authorized Windows Event Log (`.evtx`) importer** to the Phase 4 dashboard. The existing CSV, rule-based detections, Isolation Forest scoring, SQLite alert queue, and local investigation playbooks remain available.

## Requirements
- Windows 10/11
- Python 3.10–3.12 recommended
- Exported Windows `.evtx` file or normalized CSV

## Install
Open PowerShell in this extracted folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m pytest -q
python -m streamlit run app.py
```

## Import real Windows events
1. Open **Event Viewer** (`eventvwr.msc`).
2. Navigate to **Windows Logs → Security** (or System for a first test).
3. Choose **Save All Events As…** and save an `.evtx` file in a folder you can access.
4. In the dashboard, select **Upload Windows EVTX**, choose the exported file, then click **Load, detect and score**.

Exporting Security logs can require administrator or other approved permissions. If Windows reports **Access is denied**, ask an administrator or your lab/IT support to export the log for you. Do not try to bypass permissions. You can test the importer with an EVTX file you are authorized to access, or continue with the sample CSV.

## Important notes
- EVTX parsing extracts structured event fields; it does not recreate Event Viewer’s fully rendered message text.
- The fields available depend on event type. Account and source IP may be `unknown` when a record does not contain them.
- Event ID 4625 usually represents a failed logon; 4624 is a successful logon. Interpret events in context.
- ML anomaly scores are relative to the current uploaded batch and are not attack probabilities. Rule/ML alerts require human review.
- This tool is for defensive investigation of systems and logs you are authorized to access.
