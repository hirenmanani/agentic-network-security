import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
from pathlib import Path

ROOT    = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "incidents.db"

st.set_page_config(page_title="SOC Dashboard", layout="wide")
st.title("🛡️ Agentic Network Security Monitor — SOC Dashboard")

@st.cache_data(ttl=10)
def load_data():
    conn = sqlite3.connect(str(DB_PATH))
    df   = pd.read_sql_query("SELECT * FROM incidents", conn)
    conn.close()
    return df

try:
    df = load_data()

    if not df.empty:

        # ── KPI CARDS ──────────────────────────────────────────────
        sev = df['severity'].value_counts().to_dict()
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("🔴 Critical",  sev.get('critical', 0))
        c2.metric("🟠 High",      sev.get('high',     0))
        c3.metric("🟡 Medium",    sev.get('medium',   0))
        c4.metric("⚪ Low",       sev.get('low',      0))
        c5.metric("📦 Total",     len(df))

        st.divider()

        # ── CHARTS ─────────────────────────────────────────────────
        col_chart, col_action = st.columns(2)

        with col_chart:
            st.subheader("📊 Severity Breakdown (log scale)")
            sev_df = df['severity'].value_counts().reset_index()
            sev_df.columns = ['Severity', 'Count']
            order = ['critical', 'high', 'medium', 'low']
            color_map = {
                'critical': '#e74c3c',
                'high':     '#e67e22',
                'medium':   '#f1c40f',
                'low':      '#2ecc71'
            }
            sev_df['Severity'] = pd.Categorical(
                sev_df['Severity'], categories=order, ordered=True)
            sev_df = sev_df.sort_values('Severity')
            fig = px.bar(
                sev_df, x='Severity', y='Count',
                color='Severity',
                color_discrete_map=color_map,
                log_y=True,
                text='Count',
                title="Incidents by Severity (log scale)"
            )
            fig.update_traces(textposition='outside')
            fig.update_layout(showlegend=False, height=350)
            st.plotly_chart(fig, use_container_width=True)

        with col_action:
            st.subheader("🎯 Response Actions")
            act_df = df['recommended_action'].value_counts().reset_index()
            act_df.columns = ['Action', 'Count']
            action_colors = {
                'block':      '#e74c3c',
                'rate_limit': '#e67e22',
                'alert':      '#f1c40f',
                'monitor':    '#3498db'
            }
            fig2 = px.pie(
                act_df, names='Action', values='Count',
                color='Action',
                color_discrete_map=action_colors,
                title="Response Action Distribution"
            )
            fig2.update_layout(height=350)
            st.plotly_chart(fig2, use_container_width=True)

        st.divider()

        # ── CRITICAL & HIGH TABLE ──────────────────────────────────
        st.subheader("🚨 Critical & High Severity Incidents")
        critical_df = df[df['severity'].isin(['critical', 'high'])][
            ['timestamp', 'source_ip', 'threat_type',
             'severity', 'confidence', 'recommended_action',
             'is_repeat_offender']
        ].head(50)
        st.dataframe(critical_df, use_container_width=True, hide_index=True)

        st.divider()

        with st.expander("📋 Full Incident Log"):
            st.dataframe(df, use_container_width=True)

    else:
        st.warning("Database connected but incidents table is empty.")

except Exception as e:
    st.error(f"❌ Dashboard Error: {e}")
    st.info("Run `python src/security_monitor.py` to populate the database.")
