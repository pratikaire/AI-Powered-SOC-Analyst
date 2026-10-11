"""Phase 2 explainable rules retained for combined analysis."""
import hashlib
import pandas as pd

ALERT_COLUMNS = ["timestamp","severity","rule","account","source_ip","count","window_minutes","details","fingerprint"]

def _fingerprint(rule, account="", source_ip=""):
    return hashlib.sha256("|".join([rule,str(account).lower(),str(source_ip).lower()]).encode()).hexdigest()[:24]

def _alert(rule,severity,ts,account,ip,count,window,details):
    return {"timestamp":pd.Timestamp(ts).isoformat(),"severity":severity,"rule":rule,"account":account,"source_ip":ip,"count":int(count),"window_minutes":int(window),"details":details,"fingerprint":_fingerprint(rule,account,ip)}

def detect_threats(events, threshold=5, window_minutes=10, spray_accounts=5, multi_ip_threshold=3):
    if events is None or events.empty: return pd.DataFrame(columns=ALERT_COLUMNS)
    df=events.copy()
    for c in ["account","source_ip"]:
        if c not in df: df[c]="unknown"
        df[c]=df[c].fillna("unknown").astype(str).str.strip().replace("","unknown")
    df["event_id"]=pd.to_numeric(df["event_id"],errors="coerce")
    df["timestamp"]=pd.to_datetime(df["timestamp"],errors="coerce",utc=True)
    df=df.dropna(subset=["event_id","timestamp"]).copy()
    df["event_id"]=df["event_id"].astype(int); df=df.sort_values("timestamp")
    alerts=[]; delta=pd.Timedelta(minutes=int(window_minutes)); failed=df[df.event_id==4625]
    for (account,ip),g in failed.groupby(["account","source_ip"]):
        times=g.timestamp.tolist(); left=0
        for right,now in enumerate(times):
            while left<=right and now-times[left]>delta: left+=1
            count=right-left+1
            if count>=threshold:
                alerts.append(_alert("Repeated failed logons","High" if count>=threshold*2 else "Medium",now,account,ip,count,window_minutes,f"{count} failed logons for {account} from {ip} within {window_minutes} minutes. Review context."))
                break
    for ip,g in failed.groupby("source_ip"):
        g=g.sort_values("timestamp"); times=g.timestamp.tolist(); left=0
        for right,now in enumerate(times):
            while left<=right and now-times[left]>delta: left+=1
            win=g.iloc[left:right+1]; accounts=sorted(set(win.account.tolist()))
            if len(accounts)>=spray_accounts:
                alerts.append(_alert("Possible password spraying","High",now,", ".join(accounts[:8]),ip,len(win),window_minutes,f"Failed logons against {len(accounts)} accounts from {ip} in {window_minutes} minutes. Validate activity."))
                break
    for account,g in failed.groupby("account"):
        g=g.sort_values("timestamp"); times=g.timestamp.tolist(); left=0
        for right,now in enumerate(times):
            while left<=right and now-times[left]>delta: left+=1
            win=g.iloc[left:right+1]; ips=sorted(set(win.source_ip.tolist())-{"unknown"})
            if len(ips)>=multi_ip_threshold:
                alerts.append(_alert("Multiple sources targeting one account","High",now,account,", ".join(ips[:8]),len(win),window_minutes,f"{account} had failures from {len(ips)} sources within {window_minutes} minutes. Validate sources."))
                break
    for _,s in df[df.event_id==4624].iterrows():
        prior=failed[(failed.account==s.account)&(failed.source_ip==s.source_ip)&(failed.timestamp<=s.timestamp)&(failed.timestamp>=s.timestamp-delta)]
        if len(prior)>=3:
            alerts.append(_alert("Success after repeated failures","High",s.timestamp,s.account,s.source_ip,len(prior),window_minutes,f"Success followed {len(prior)} recent failures for {s.account} from {s.source_ip}. Investigate context."))
    for _,e in df[df.event_id==4672].iterrows():
        alerts.append(_alert("Privileged logon requires review","Low",e.timestamp,e.account,e.source_ip,1,window_minutes,f"Event 4672 assigned special privileges to {e.account}; this may be normal for administrators."))
    if not alerts: return pd.DataFrame(columns=ALERT_COLUMNS)
    return pd.DataFrame(alerts,columns=ALERT_COLUMNS).sort_values(["count","timestamp"]).drop_duplicates("fingerprint",keep="last").reset_index(drop=True)
