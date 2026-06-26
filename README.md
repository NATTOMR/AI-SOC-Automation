# AI-SOC-Automation
# Autonomous AI Cyber Threat Intelligence (CTI) & SOAR Pipeline

## 📌 Project Overview
This project is an intermediate-level **Security Operations Center (SOC) Automation Pipeline** designed to combat alert fatigue and drastically lower Mean Time to Resolution (MTTR). It simulates a Security Information and Event Management (SIEM) alert, automatically orchestrates Threat Intelligence lookup via the **VirusTotal API**, dispatches the contextualized data to a local LLM (**Llama 3 via Ollama**) acting as a virtual Tier-2 SOC Analyst, and triggers automated defensive playbooks (SOAR) through an interactive **Streamlit Web Dashboard**.

---

## 🏗️ Architecture & Workflow

1. **Ingestion**: The pipeline monitors and ingests raw JSON security alerts (e.g., potential data exfiltration).
2. **Enrichment**: A Python engine dynamically extracts indicators of compromise (IoCs) like suspicious external destination IPs and queries global threat registries.
3. **AI Triage**: The structured logs and API context are sent to a private, locally hosted Llama 3 instance to deliver automated analysis, severity ratings, and mitigation actions.
4. **Response Orchestration**: If a high-severity threat is confirmed, the playbook generates a structured markdown incident ticket and appends the malicious IoC to a network blocklist.

---

## 🛠️ Core Capabilities & Tech Stack

* **Front-End Interface**: Streamlit Web Framework (Interactive User/Analyst Interface)
* **Automation Controller**: Python 3.10+ (`requests`, `python-dotenv`)
* **Threat Intelligence Engines**: VirusTotal API v3
* **Local AI Framework**: Ollama (`llama3` model)
* **Secure Environment Configuration**: Decoupled api keys using `.env` files

---

## 🚀 Key Security Engineering Metrics Demonstrated

* **Alert Fatigue Reduction**: Condenses massive, noisy JSON log formats down into clean, structured analyst summaries instantly.
* **Triage Optimization**: Accelerates Tier-1 alert validation workflows down from an average of 15 minutes to under **10 seconds** using local agentic AI orchestration.
* **Privacy-Centric Architecture**: Leverages local open-source LLMs to ensure proprietary enterprise security logs never leave the organization's host boundaries.

---

## 💻 How to Install and Run Locally

### 1. Prerequisites
Ensure you have Python 3.10+ installed and [Ollama for Windows](https://ollama.com/) running. Pull the required model:
```bash
ollama run llama3
```

## 2. Installation
Clone this repository and navigate into the directory:
```git clone [https://github.com/NATTOMR/AI-SOC-Automation.git](https://github.com/NATTOMR/AI-SOC-Automation.git)
cd AI-SOC-Automation
```
Set up a Python virtual environment and install the required dependencies:
```python -m venv venv
.\venv\Scripts\activate
pip install requests python-dotenv streamlit
```
## 3. Environment Setup
Create a .env file in the root directory to keep your API credentials safe and separated from the repository logic:

Code snippet
``` VT_API_KEY="your_actual_virustotal_api_key_here"
```
## 4. Running the Dashboard
Launch the interactive web application:
```
streamlit run dashboard.py
Open your browser and navigate to http://localhost:8501 to interface with the active SOAR pipeline.
```
## 📊 Pipeline Artifact Outputs
Sample Ingested Alert (siem_alert.json)
``` JSON
{
  "alert_id": "ALERT-2026-0042",
  "source_ip": "192.168.1.105",
  "destination_ip": "185.220.101.5",
  "destination_port": 443,
  "protocol": "TCP",
  "bytes_transferred": 894000,
  "signature": "Potential Data Exfiltration over TOR Network"
}
```
## Generated Containment Actions
 - incident_report.md: Generated dynamically by the Llama 3 engine containing formal threat verdicts, executive summaries, and explicit remediation steps.

- blocked_ips.txt: Appends the confirmed rogue destination IP (185.220.101.5) automatically to a localized firewall perimeter blocklist file to demonstrate automated containment.
