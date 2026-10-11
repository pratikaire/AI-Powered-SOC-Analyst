"""SQLite persistence and alert status tracking."""
import sqlite3
from pathlib import Path
import pandas as pd
DEFAULT_DB=Path("data/soc_analyst.db")

def _columns(conn,table): return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}

def init_db(db_path=DEFAULT_DB):
    Path(db_path).parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(db_path) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT,event_id INTEGER,computer TEXT,account TEXT,source_ip TEXT,logon_type TEXT,status TEXT,message TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT,severity TEXT,rule TEXT,account TEXT,source_ip TEXT,count INTEGER,window_minutes INTEGER,details TEXT)""")
        cols=_columns(c,"alerts")
        for col,decl in {"status":"TEXT NOT NULL DEFAULT 'Open'","fingerprint":"TEXT NOT NULL DEFAULT ''","first_seen":"TEXT NOT NULL DEFAULT ''","last_seen":"TEXT NOT NULL DEFAULT ''"}.items():
            if col not in cols: c.execute(f"ALTER TABLE alerts ADD COLUMN {col} {decl}")
        c.execute("UPDATE alerts SET fingerprint='legacy-' || id WHERE fingerprint=''")
        c.execute("UPDATE alerts SET first_seen=timestamp WHERE first_seen=''")
        c.execute("UPDATE alerts SET last_seen=timestamp WHERE last_seen=''")

def save_events(events,db_path=DEFAULT_DB):
    init_db(db_path)
    if events is None or events.empty: return 0
    cols=["timestamp","event_id","computer","account","source_ip","logon_type","status","message"]
    rows=[tuple(str(v) for v in r) for r in events.reindex(columns=cols).fillna("").itertuples(index=False,name=None)]
    with sqlite3.connect(db_path) as c: c.executemany("INSERT INTO events (timestamp,event_id,computer,account,source_ip,logon_type,status,message) VALUES (?,?,?,?,?,?,?,?)",rows)
    return len(rows)

def upsert_alerts(alerts,db_path=DEFAULT_DB):
    init_db(db_path)
    if alerts is None or alerts.empty: return 0
    added=0
    with sqlite3.connect(db_path) as c:
        for _,a in alerts.iterrows():
            fp=str(a.get("fingerprint","")); old=c.execute("SELECT id FROM alerts WHERE fingerprint=? LIMIT 1",(fp,)).fetchone()
            ts=str(a.get("timestamp",""))
            vals=(ts,str(a.get("severity","Low")),str(a.get("rule","")),str(a.get("account","")),str(a.get("source_ip","")),int(a.get("count",0)),int(a.get("window_minutes",10)),str(a.get("details","")))
            if old:
                c.execute("UPDATE alerts SET timestamp=?,severity=?,rule=?,account=?,source_ip=?,count=?,window_minutes=?,details=?,last_seen=? WHERE id=?",(*vals,ts,old[0]))
            else:
                c.execute("INSERT INTO alerts (timestamp,severity,rule,account,source_ip,count,window_minutes,details,status,fingerprint,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?, 'Open', ?, ?, ?)",(*vals,fp,ts,ts)); added+=1
    return added

def update_alert_status(alert_id,status,db_path=DEFAULT_DB):
    if status not in {"Open","Investigating","Closed"}: raise ValueError("Invalid status")
    init_db(db_path)
    with sqlite3.connect(db_path) as c: c.execute("UPDATE alerts SET status=? WHERE id=?",(status,int(alert_id)))

def load_events(db_path=DEFAULT_DB):
    init_db(db_path)
    with sqlite3.connect(db_path) as c: return pd.read_sql_query("SELECT * FROM events ORDER BY timestamp DESC",c)

def load_alerts(db_path=DEFAULT_DB):
    init_db(db_path)
    with sqlite3.connect(db_path) as c: return pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC",c)
