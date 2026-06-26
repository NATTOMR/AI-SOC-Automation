import streamlit as st
import os
import json
import requests
from dotenv import load_dotenv

# Load configurations
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# Set up Web Page Configuration
st.set_page_config(page_title="AI-Driven SOAR Dashboard", layout="wide")
st.title("🤖 Autonomous AI SOC Analyst Dashboard")
st.markdown("---")

# 1. Helper Functions
def load_siem_alert():
    with open("siem_alert.json", "r") as f:
        return json.load(f)

def check_virus_total(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0), stats.get('suspicious', 0)
        return 0, 0
    except:
        return 0, 0

def query_ollama_ai(alert_data, intel_summary):
    system_prompt = (
        "You are an advanced Tier 2 SOC Analyst. Analyze the provided SIEM alert and Threat Intel. "
        "Provide a clear triage verdict using this format:\n\n"
        "## VERDICT: [True Positive / False Positive]\n"
        "## SEVERITY: [Low / Medium / High]\n"
        "### Executive Summary:\n[Summary]\n"
        "### Recommended Mitigation:\n[Actions]"
    )
    user_content = f"Alert:\n{json.dumps(alert_data)}\n\nIntel:\n{intel_summary}"
    url = "http://localhost:11434/api/generate"
    payload = {"model": "llama3", "prompt": f"{system_prompt}\n\n{user_content}", "stream": False}
    try:
        res = requests.post(url, json=payload)
        return res.json().get("response", "No response")
    except Exception as e:
        return f"Error connecting to local AI: {str(e)}"

# 2. Sidebar / Control Layout
st.sidebar.header("🛡️ Alert Controls")
mock_alert = load_siem_alert()

if st.sidebar.button("Fetch Latest SIEM Alert"):
    st.sidebar.success(f"Loaded {mock_alert['alert_id']}")

# 3. Main Dashboard Layout (Columns)
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("🚨 Raw Ingested SIEM Alert")
    st.json(mock_alert)
    
    st.subheader("🔍 Threat Intelligence Enrichment")
    target_ip = mock_alert["destination_ip"]
    
    if st.button("Run Threat Intel Lookup"):
        mal, susp = check_virus_total(target_ip)
        st.metric(label="VirusTotal Malicious Flags", value=f"{mal} Vendors", delta="Threat Detected" if mal > 0 else "Clean")
        st.session_state['intel_text'] = f"VirusTotal found {mal} malicious and {susp} suspicious indicators."
        st.info(st.session_state['intel_text'])

with col2:
    st.subheader("🧠 Local AI Analyst Triage")
    if st.button("🚀 Dispatch to Llama 3 AI"):
        if 'intel_text' not in st.session_state:
            st.warning("Please run Threat Intel Lookup first to gather context!")
        else:
            with st.spinner("AI Analyst is evaluating data..."):
                ai_report = query_ollama_ai(mock_alert, st.session_state['intel_text'])
                st.markdown(ai_report)
                
                # Automated response logging simulation
                st.success("🔒 Playbook Executed: Firewall rule updated & incident ticket created.")
                with open("blocked_ips.txt", "a") as b:
                    b.write(f"{target_ip}\n")