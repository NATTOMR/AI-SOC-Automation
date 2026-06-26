import os
import json
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def load_siem_alert(file_path):
    """Loads the simulated SIEM alert JSON file."""
    with open(file_path, 'r') as f:
        return json.load(f)

def check_virus_total(ip_address):
    """Queries VirusTotal API for IP reputation."""
    if not VT_API_KEY or VT_API_KEY == "your_actual_virustotal_api_key":
        return "No valid VirusTotal API key found. Skipping live lookup."

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            return f"VirusTotal Results: {malicious_count} vendors flagged as malicious, {suspicious_count} flagged as suspicious."
        else:
            return f"VirusTotal API Error: Status Code {response.status_code}"
    except Exception as e:
        return f"Error connecting to VirusTotal: {str(e)}"

def ai_triage_analyst(alert_data, intel_data):
    """Sends context to local Ollama (Llama3) for incident triage."""
    print("[*] Dispatching data to local AI SOC Analyst (Llama 3)...")
    
    # Crafting the expert prompt
    system_prompt = (
        "You are an advanced Tier 2 SOC Analyst. Analyze the provided SIEM alert and its accompanying "
        "Threat Intelligence data. Provide a clear triage verdict using this strict format:\n\n"
        "## VERDICT: [True Positive / False Positive]\n"
        "## SEVERITY: [Low / Medium / High]\n"
        "### Executive Summary:\n[Your short analysis summary here]\n"
        "### Recommended Mitigation Actions:\n[Action steps here]"
    )
    
    user_content = f"SIEM Alert Details:\n{json.dumps(alert_data, indent=2)}\n\nThreat Intelligence Enrichment:\n{intel_data}"
    
    # Ollama local API endpoint
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "llama3",
        "prompt": f"{system_prompt}\n\nTask:\n{user_content}",
        "stream": False
    }
    
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            return response.json().get("response", "No response text received.")
        else:
            return f"Ollama API Error: Status Code {response.status_code}"
    except Exception as e:
        return f"Could not connect to Ollama. Make sure 'ollama run llama3' is working. Error: {str(e)}"

def execute_automated_response(verdict_text, target_ip):
    """Parses the AI verdict and triggers automated containment playbooks."""
    print("\n[*] Triggering Automated SOAR Playbooks based on AI Verdict...")
    
    # Check if the AI marked this as High severity
    if "SEVERITY: High" in verdict_text or "Verdict: True Positive" in verdict_text:
        print("[⚡] CRITICAL ACTION TRIGGERED: High Severity Threat Confirmed by AI.")
        
        # Action 1: Generate an Incident Report File
        report_filename = "incident_report.md"
        with open(report_filename, "w") as report_file:
            report_file.write(verdict_text)
        print(f"[✔] Action 1 Complete: Formal incident ticket generated as '{report_filename}'")
        
        # Action 2: Simulate Firewall Blocking
        blocklist_filename = "blocked_ips.txt"
        with open(blocklist_filename, "a") as block_file:
            block_file.write(f"{target_ip}\n")
        print(f"[✔] Action 2 Complete: Suspicious IP {target_ip} appended to '{blocklist_filename}' (Simulated Firewall Block)")
        
    else:
        print("[ℹ] Playbook Action: Low/Medium threat detected. Logged for standard review.")

if __name__ == "__main__":
    # 1. Load the mock alert
    alert = load_siem_alert("siem_alert.json")
    target_ip = alert["destination_ip"]
    print(f"[+] Loaded Alert {alert['alert_id']} tracking target IP: {target_ip}")
    
    # 2. Run Threat Intel Enrichment
    intel_report = check_virus_total(target_ip)
    print(f"[+] Enrichment Data gathered: {intel_report}\n")
    
    # 3. AI Triage
    ai_verdict = ai_triage_analyst(alert, intel_report)
    print("\n=================== AI ANALYST TRIAGE REPORT ===================")
    print(ai_verdict)
    print("================================================================")
    
    # 4. Automated Response Action
    execute_automated_response(ai_verdict, target_ip)
    # 2. Run Threat Intel Enrichment
    intel_report = check_virus_total(target_ip)
    print(f"[+] Enrichment Data gathered: {intel_report}\n")
    
    # 3. AI Triage
    ai_verdict = ai_triage_analyst(alert, intel_report)
    print("\n=================== AI ANALYST TRIAGE REPORT ===================")
    print(ai_verdict)
    print("================================================================")