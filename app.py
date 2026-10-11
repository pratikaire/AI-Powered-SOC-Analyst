from pathlib import Path
import pandas as pd
import streamlit as st
from src.preprocessing import normalize_events
from src.detection import detect_threats
from src.ml_anomaly import score_anomalies
from src.storage import init_db,save_events,load_events,upsert_alerts,load_alerts,update_alert_status
from src.investigation import build_investigation
from src.evtx_import import parse_evtx_bytes

DB=Path("data/soc_analyst.db"); SAMPLE=Path("data/sample_security_logs.csv")
st.set_page_config(page_title="AI-Powered SOC Analyst",page_icon="🛡️",layout="wide")
st.title("🛡️ AI-Powered SOC Analyst")
st.caption("Phase 5 • Windows EVTX Import + Rule-Based Detection + ML Anomaly Scoring + Investigation Assistant")
st.warning("Isolation Forest is an unsupervised baseline. An anomaly is unusual relative to the imported batch, not proof of an attack. Synthetic sample results are for learning.")
init_db(DB)

with st.sidebar:
    st.header("Import security logs")
    source=st.radio("Data source",["Built-in sample CSV","Upload CSV","Upload Windows EVTX"])
    uploaded=st.file_uploader("Upload security log file",type=["csv"] if source=="Upload CSV" else (["evtx"] if source=="Upload Windows EVTX" else [])) if source!="Built-in sample CSV" else None
    st.divider()
    st.subheader("Rule settings")
    threshold=st.number_input("Failed logons per account/source",2,100,5)
    window=st.number_input("Detection window (minutes)",1,1440,10)
    spray=st.number_input("Distinct accounts for spray alert",2,100,5)
    multi=st.number_input("Distinct sources targeting one account",2,100,3)
    st.divider()
    st.subheader("ML settings")
    contamination=st.slider("Expected anomaly fraction",0.05,0.40,0.15,0.05)
    run=st.button("Load, detect and score",type="primary",use_container_width=True)

if run:
    try:
        if source=="Built-in sample CSV":
            raw=pd.read_csv(SAMPLE)
        elif uploaded is not None and source=="Upload CSV":
            raw=pd.read_csv(uploaded)
        elif uploaded is not None and source=="Upload Windows EVTX":
            raw=parse_evtx_bytes(uploaded.getvalue())
            st.info("Imported Windows EVTX records. Review the normalized fields; some event types do not include account or source IP details.")
        else:
            st.error("Choose a data source and upload the requested file."); raw=None
        if raw is not None:
            new=normalize_events(raw)
            if len(new)<5: st.error("At least 5 valid events are required for ML scoring.")
            else:
                inserted=save_events(new,DB)
                # Score the current imported batch to keep the result interpretable.
                scored=score_anomalies(new,contamination=float(contamination))
                st.session_state["ml_results"]=scored
                rule_alerts=detect_threats(new,int(threshold),int(window),int(spray),int(multi))
                added=upsert_alerts(rule_alerts,DB)
                st.success(f"Processed {len(new)} events; stored {inserted} event rows; found {len(rule_alerts)} rule alert(s), {added} new alert(s); scored {len(scored)} events with Isolation Forest.")
    except Exception as e:
        st.error(f"Analysis failed: {e}")

events=load_events(DB); alerts=load_alerts(DB)
a,b,c,d=st.columns(4)
a.metric("Stored events",f"{len(events):,}")
failed=int((pd.to_numeric(events.event_id,errors="coerce")==4625).sum()) if not events.empty else 0
b.metric("Failed logons (4625)",f"{failed:,}")
c.metric("Rule alerts",f"{len(alerts):,}")
d.metric("Open alerts",f"{int((alerts.status=='Open').sum()):,}" if not alerts.empty else "0")

t1,t2,t3,t4,t5=st.tabs(["Investigation Queue","ML Anomalies","Event Explorer","Detection Guide","Investigation Assistant"])
with t1:
    st.subheader("Rule-based investigation queue")
    if alerts.empty: st.info("Load the sample CSV or upload a CSV and run analysis.")
    else:
        f1,f2=st.columns(2)
        sev=f1.multiselect("Severity",["High","Medium","Low"],default=["High","Medium","Low"])
        sts=f2.multiselect("Status",["Open","Investigating","Closed"],default=["Open","Investigating","Closed"])
        view=alerts[alerts.severity.isin(sev)&alerts.status.isin(sts)]
        st.dataframe(view[["id","timestamp","severity","rule","account","source_ip","count","status","details"]],use_container_width=True,hide_index=True)
        st.download_button("Download rule alerts",view.to_csv(index=False).encode(),"soc_rule_alerts.csv","text/csv")
        opts={f"#{int(r.id)} · {r.rule} · {r.account} · {r.status}":int(r.id) for r in alerts.itertuples()}
        if opts:
            label=st.selectbox("Choose alert to update",list(opts))
            status=st.selectbox("New status",["Open","Investigating","Closed"])
            if st.button("Update alert status"):
                update_alert_status(opts[label],status,DB); st.success("Status saved."); st.rerun()
with t2:
    st.subheader("Isolation Forest anomaly results")
    scored=st.session_state.get("ml_results")
    if scored is None:
        st.info("Run analysis to score the current CSV batch. ML results are held for this dashboard session.")
    else:
        anomalies=scored[scored.anomaly_flag]
        m1,m2,m3=st.columns(3)
        m1.metric("Events scored",len(scored)); m2.metric("Flagged as unusual",len(anomalies)); m3.metric("Expected anomaly fraction",f"{contamination:.0%}")
        st.caption("Higher anomaly score means more unusual according to this fitted model. Scores are relative to this batch and are not probabilities.")
        st.dataframe(scored[["timestamp","event_id","account","source_ip","anomaly_flag","anomaly_score","ml_reason"]],use_container_width=True,hide_index=True)
        st.download_button("Download ML scores",scored.to_csv(index=False).encode(),"soc_ml_anomaly_scores.csv","text/csv")
with t3:
    st.subheader("Normalized events")
    if events.empty: st.info("No events imported yet.")
    else:
        ids=sorted(pd.to_numeric(events.event_id,errors="coerce").dropna().astype(int).unique())
        selected=st.multiselect("Filter by Event ID",ids,default=ids)
        filtered=events[pd.to_numeric(events.event_id,errors="coerce").isin(selected)]
        st.dataframe(filtered,use_container_width=True,hide_index=True)
        st.download_button("Download events",filtered.to_csv(index=False).encode(),"normalized_security_events.csv","text/csv")
with t4:
    st.markdown("""
    **Rule detections:** repeated failures, possible password spraying, multiple sources targeting one account, success after repeated failures, and privileged-logon review.

    **ML method:** Isolation Forest, an unsupervised anomaly-detection algorithm. It learns patterns from the current batch and flags a configurable fraction of events as unusual.

    **Windows EVTX import:** Upload an authorized `.evtx` export from Event Viewer. Security log export may require an administrator or approved access; do not attempt to bypass organizational permissions. Parsed event fields vary by event type, and some account/IP fields may be unknown.

    **Important limitations:** This small sample is synthetic and not representative of normal enterprise traffic. A meaningful model needs a larger, representative baseline and human-reviewed evaluation. Event-level feature counts are batch-level features in this starter, so treat scores as educational triage signals only.
    """)

with t5:
    st.subheader("Local investigation assistant — no API key required")
    st.caption("Creates a structured triage checklist from alert fields using transparent playbooks. It does not call a cloud AI service.")
    source_kind=st.radio("Finding source",["Rule alert","ML anomaly"],horizontal=True,key="investigation_source")
    if source_kind=="Rule alert":
        if alerts.empty:
            st.info("Load data and generate rule alerts first.")
        else:
            choices={f"#{int(r.id)} · {r.rule} · {r.account} · {r.severity}":r._asdict() for r in alerts.itertuples(index=False)}
            selected_label=st.selectbox("Select an alert",list(choices),key="investigation_rule_choice")
            if st.button("Build investigation guide",type="primary",key="build_rule_guide"):
                st.session_state["investigation_guide"]=build_investigation(choices[selected_label],source="rule alert")
    else:
        scored=st.session_state.get("ml_results")
        if scored is None or scored.empty:
            st.info("Run analysis first to score the imported event batch.")
        else:
            unusual=scored[scored["anomaly_flag"]].copy()
            if unusual.empty:
                st.warning("No events are currently flagged. Re-run analysis or inspect the highest anomaly scores in the ML Anomalies tab.")
            else:
                unusual=unusual.sort_values("anomaly_score",ascending=False)
                ml_choices={f"{r.timestamp} · Event {r.event_id} · {r.account} · score {r.anomaly_score:.5f}":r._asdict() for r in unusual.itertuples(index=False)}
                selected_ml=st.selectbox("Select an unusual event",list(ml_choices),key="investigation_ml_choice")
                if st.button("Build investigation guide",type="primary",key="build_ml_guide"):
                    st.session_state["investigation_guide"]=build_investigation(ml_choices[selected_ml],source="ML anomaly")
    guide=st.session_state.get("investigation_guide")
    if guide:
        st.markdown(f"### {guide['title']}")
        st.markdown("**Why it was flagged**")
        st.write(guide["why_flagged"])
        st.markdown("**Available evidence**")
        for item in guide["evidence"]: st.markdown(f"- {item}")
        st.markdown("**Investigation checklist**")
        for i,item in enumerate(guide["checks"],1): st.checkbox(item,key=f"investigation_check_{i}_{hash(item)}")
        st.markdown("**Recommended next actions**")
        for item in guide["recommended_actions"]: st.markdown(f"- {item}")
        st.warning(guide["limitations"])
        report="\n".join([guide["title"],"", "Why flagged: "+guide["why_flagged"],"", "Evidence:", *["- "+x for x in guide["evidence"]],"", "Investigation checklist:", *["- [ ] "+x for x in guide["checks"]],"", "Recommended next actions:", *["- "+x for x in guide["recommended_actions"]],"", "Limitations: "+guide["limitations"]])
        st.download_button("Download investigation notes",report.encode("utf-8"),"soc_investigation_notes.txt","text/plain")
