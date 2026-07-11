import streamlit as st
import pandas as pd
from parser import parse_logs
from detector import detect_threats

# ======================================================
# Page Configuration
# ======================================================

st.set_page_config(
    page_title="AI Cybersecurity Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# ======================================================
# Title
# ======================================================

st.title("🛡️ AI Cybersecurity Log Analyzer")
st.markdown(
    "Analyze cybersecurity log files using **Python + AI + Threat Detection**"
)

st.divider()

# ======================================================
# File Upload
# ======================================================

uploaded_file = st.file_uploader(
    "📂 Upload Log File",
    type=["txt", "log", "csv"]
)

# ======================================================
# Main Program
# ======================================================

if uploaded_file is not None:

    st.success("✅ File Uploaded Successfully!")

    # Read uploaded file
    log_text = uploaded_file.read().decode("utf-8")

    # Parse Logs
    parsed_logs = parse_logs(log_text)

    # Detect Threats
    detected_threats = detect_threats(parsed_logs)

    # Convert into DataFrames
    parsed_df = pd.DataFrame(parsed_logs)
    threat_df = pd.DataFrame(detected_threats)

    # ==================================================
    # Tabs
    # ==================================================

    dashboard_tab, threat_tab, parsed_tab, raw_tab = st.tabs([
        "📊 Dashboard",
        "🚨 Threat Analysis",
        "📋 Parsed Logs",
        "📄 Original Log"
    ])

    # ==================================================
    # Dashboard
    # ==================================================

    with dashboard_tab:

        st.subheader("📊 Security Dashboard")

        total_logs = len(parsed_df)

        total_threats = len(
            threat_df[
                threat_df["attack_type"] != "Normal Activity"
            ]
        )

        critical = len(
            threat_df[
                threat_df["severity"] == "Critical"
            ]
        )

        high = len(
            threat_df[
                threat_df["severity"] == "High"
            ]
        )

        medium = len(
            threat_df[
                threat_df["severity"] == "Medium"
            ]
        )

        low = len(
            threat_df[
                threat_df["severity"] == "Low"
            ]
        )

        c1, c2, c3, c4, c5 = st.columns(5)

        c1.metric("📄 Total Logs", total_logs)
        c2.metric("🚨 Threats", total_threats)
        c3.metric("🔴 Critical", critical)
        c4.metric("🟠 High", high)
        c5.metric("🟡 Medium + Low", medium + low)

        st.info(
            "This dashboard provides an overview of detected cybersecurity threats."
        )
        
    # ==================================================
    # Threat Analysis
    # ==================================================

    with threat_tab:

        st.subheader("🚨 Threat Detection Results")

    # -------------------------------
    # Search & Filter
    # -------------------------------

    col1, col2, col3 = st.columns(3)

    with col1:
        search_ip = st.text_input(
        "🔍 Search by IP Address",
        placeholder="Example: 192.168.1.10"
    )

    with col2:
        search_user = st.text_input(
        "👤 Search Username",
        placeholder="Example: admin"
    )

    with col3:
        severity_filter = st.selectbox(
        "⚠️ Filter by Severity",
        ["All", "Critical", "High", "Medium", "Low"]
    )
    # -------------------------------
    # Apply Filters
    # -------------------------------

    filtered_df = threat_df.copy()

    # Search by IP
    if search_ip:
        filtered_df = filtered_df[
            filtered_df["ip_address"].str.contains(
                search_ip,
                case=False,
                na=False
            )
        ]
    # Search by Username
    if search_user:
        filtered_df = filtered_df[
        filtered_df["username"].str.contains(
            search_user,
            case=False,
            na=False
        )
    ]
    
    # Filter by Severity
    if severity_filter != "All":
        filtered_df = filtered_df[
            filtered_df["severity"] == severity_filter
        ]

    # -------------------------------
    # Show Results
    # -------------------------------

    if filtered_df.empty:
        st.warning("No matching threats found.")
    else:
        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True
        )
    # ------------------------------------
    # Download Threat Report
    # ------------------------------------

    csv = filtered_df.to_csv(index=False).encode("utf-8")

    st.download_button(
    label="⬇ Download Threat Report (CSV)",
    data=csv,
    file_name="threat_report.csv",
    mime="text/csv"
    )

    # ==================================================
    # Parsed Logs
    # ==================================================

    with parsed_tab:

        st.subheader("📋 Parsed Logs")

        if parsed_df.empty:
            st.warning("No parsed logs available.")
        else:
            st.dataframe(
                parsed_df,
                use_container_width=True,
                hide_index=True
            )

    # ==================================================
    # Original Uploaded Log
    # ==================================================

    with raw_tab:

        st.subheader("📄 Original Uploaded Log")

        st.code(log_text)

# ======================================================
# No File Uploaded
# ======================================================

else:

    st.info("👆 Please upload a log file to begin analysis.")

    st.markdown("---")

    st.markdown("### 📌 Supported Log Format")

    st.code(
"""2026-07-11 10:30:15 INFO User admin login success from 192.168.1.10 port 22

2026-07-11 10:35:42 WARNING Login failed for user admin from 192.168.1.20 port 22

2026-07-11 10:40:15 ERROR SQL Injection detected from 192.168.1.30

2026-07-11 10:45:11 CRITICAL Malware detected on host 192.168.1.50"""
    )