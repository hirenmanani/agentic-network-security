import streamlit as st
import pandas as pd
import sqlite3
from pathlib import Path

# Dynamic pathing for your nested structure
ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "incidents.db"

st.set_page_config(page_title="SOC Dashboard", layout="wide")
st.title("🛡️ Network Security SOC Dashboard")


@st.cache_data(ttl=10)
def load_data():
    conn = sqlite3.connect(str(DB_PATH))
    # Fetch all data from the incidents table
    df = pd.read_sql_query("SELECT * FROM incidents", conn)
    conn.close()
    return df


try:
    df = load_data()
    if not df.empty:
        # DATA SANITIZATION: Prevents frontend crashes
        df = df.astype(str)

        # Metrics
        st.metric("Total Threats Detected", len(df))

        # Table
        st.subheader("📋 Recent Incident Logs")
        st.dataframe(df, use_container_width=True)

        # Chart
        st.subheader("📊 Severity Breakdown")
        st.bar_chart(df['severity'].value_counts())
    else:
        st.warning("Database is connected, but the incidents table is empty.")
except Exception as e:
    st.error(f"❌ Dashboard Crash: {e}")
    st.info("Try running 'python3 src/main.py' again to refresh the database.")
