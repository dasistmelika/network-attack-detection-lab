import streamlit as st
import pandas as pd

st.set_page_config(page_title="Network Attack Detection Dashboard", layout="wide")
st.title("🛡️ Network Attack Detection Dashboard")

df = pd.read_csv("alerts.csv")

# ---------- خلاصه آماری ----------
col1, col2, col3 = st.columns(3)
col1.metric("Total Alerts", len(df))
col2.metric("High Severity", len(df[df["severity"] == "High"]))
col3.metric("Unique Attack Types", df["attack_type"].nunique())

st.divider()

# ---------- تایم‌لاین حمله‌ها ----------
st.subheader("Attack Timeline")
timeline_df = df.copy()
timeline_df["timestamp"] = pd.to_datetime(timeline_df["timestamp"], errors="coerce")
st.scatter_chart(timeline_df, x="timestamp", y="attack_type", color="severity")

# ---------- نمودار میله‌ای ----------
col4, col5 = st.columns(2)
with col4:
    st.subheader("Attack Type Frequency")
    st.bar_chart(df["attack_type"].value_counts())

with col5:
    st.subheader("Most Active Source IPs")
    st.bar_chart(df["src_ip"].value_counts())

st.divider()

# ---------- توپولوژی ساده ----------
st.subheader("Network Topology")
attacked = len(df) > 0
dot = f"""
digraph {{
    rankdir=LR;
    attacker [label="Attacker\\n192.168.222.130" shape=box style=filled fillcolor=lightblue];
    victim [label="Victim\\n192.168.222.128" shape=box style=filled fillcolor={'red' if attacked else 'lightgreen'}];
    attacker -> victim [label="attacks"];
}}
"""
st.graphviz_chart(dot)

st.divider()

# ---------- جدول کامل با تگ MITRE ----------
st.subheader("All Alerts (with MITRE ATT&CK mapping)")
st.dataframe(df, width='stretch')
