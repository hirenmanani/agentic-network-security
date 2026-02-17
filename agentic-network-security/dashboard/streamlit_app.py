# dashboard/streamlit_app.py
from incident_memory import IncidentMemory
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
sys.path.append('../src')


st.set_page_config(page_title="Network Security Monitor", layout="wide")

# Initialize memory manager


@st.cache_resource
def get_memory_manager():
    return IncidentMemory('../data/incidents.db')


memory = get_memory_manager()

# Title
st.title("🛡️ Agentic Network Security Monitor Dashboard")

# Sidebar filters
st.sidebar.header("Filters")
time_range = st.sidebar.selectbox(
    "Time Range",
    ["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"]
)

severity_filter = st.sidebar.multiselect(
    "Severity",
    ["critical", "high", "medium", "low"],
    default=["critical", "high", "medium", "low"]
)

# Get data
incidents = memory.get_recent_incidents(limit=1000)
stats = memory.get_statistics()

if incidents:
    # Convert to DataFrame
    df = pd.DataFrame(incidents)
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Apply filters
    df = df[df['severity'].isin(severity_filter)]

    # Metrics row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Incidents", stats['total_incidents'])

    with col2:
        critical_count = stats['severity_distribution'].get('critical', 0)
        st.metric("Critical Threats", critical_count, delta=None)

    with col3:
        st.metric("Unique IPs", stats['unique_ips'])

    with col4:
        blocked = stats['action_distribution'].get('block', 0)
        st.metric("IPs Blocked", blocked)

    # Charts row
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Incidents Over Time")

        # Group by hour
        df['hour'] = df['timestamp'].dt.floor('H')
        hourly = df.groupby('hour').size().reset_index(name='count')

        fig = px.line(hourly, x='hour', y='count',
                      title='Incident Frequency',
                      labels={'hour': 'Time', 'count': 'Number of Incidents'})
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Threat Distribution")

        # Flatten threat types
        all_threats = []
        for threats in df['threat_types']:
            all_threats.extend(threats)

        threat_counts = pd.Series(all_threats).value_counts()

        fig = px.pie(values=threat_counts.values, names=threat_counts.index,
                     title='Attack Types')
        st.plotly_chart(fig, use_container_width=True)

    # Severity and action distribution
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Severity Distribution")
        severity_counts = df['severity'].value_counts()

        fig = go.Figure(data=[go.Bar(
            x=severity_counts.index,
            y=severity_counts.values,
            marker_color=['red', 'orange', 'yellow', 'green']
        )])
        fig.update_layout(xaxis_title="Severity", yaxis_title="Count")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Response Actions")
        action_counts = df['response_action'].value_counts()

        fig = px.bar(x=action_counts.index, y=action_counts.values,
                     labels={'x': 'Action', 'y': 'Count'})
        st.plotly_chart(fig, use_container_width=True)

    # Top offenders
    st.subheader("Top Offending IPs")
    top_ips = df['source_ip'].value_counts().head(10)

    top_df = pd.DataFrame({
        'IP Address': top_ips.index,
        'Incident Count': top_ips.values
    })

    # Add reputation scores
    reputations = []
    for ip in top_df['IP Address']:
        history = memory.get_ip_history(ip)
        if history:
            reputations.append(f"{history['reputation_score']:.1f}")
        else:
            reputations.append("N/A")

    top_df['Reputation'] = reputations

    st.dataframe(top_df, use_container_width=True)

    # Recent incidents table
    st.subheader("Recent Incidents")

    recent_df = df.head(20)[['timestamp', 'source_ip', 'threat_types',
                             'severity', 'confidence', 'response_action']]
    recent_df['threat_types'] = recent_df['threat_types'].apply(
        lambda x: ', '.join(x))
    recent_df['confidence'] = recent_df['confidence'].round(2)

    st.dataframe(recent_df, use_container_width=True)

else:
    st.info("No incidents recorded yet. Process some logs to see data.")

# Refresh button
if st.sidebar.button("Refresh Data"):
    st.rerun()
