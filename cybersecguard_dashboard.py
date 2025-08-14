import streamlit as st
import random
import time
from datetime import datetime

st.set_page_config(page_title="CyberSecGuard Dashboard", layout="wide")

st.markdown("""
    <style>
    .reportview-container {
        background-color: #0e1117;
        color: white;
    }
    .stButton>button {
        background-color: #FF4B4B;
        color: white;
        border-radius: 8px;
        height: 3em;
        width: 100%;
        font-weight: bold;
    }
    .success {color: #00ff00; font-weight: bold;}
    .warning {color: #ffaa00; font-weight: bold;}
    .critical {color: #ff3333; font-weight: bold;}
    </style>
""", unsafe_allow_html=True)

known_bad_ips = {
    "192.168.10.45": "Malware Command & Control",
    "203.0.113.99": "Phishing Server",
    "45.67.89.101": "DDoS Botnet Node"
}

attack_types = [
    "Phishing Email",
    "Malware Injection",
    "DDoS Attack",
    "Ransomware",
    "Port Scanning",
    "Brute Force Login"
]

def current_time():
    return datetime.now().strftime("%H:%M:%S")

def log_event(msg, level="info"):
    if level == "success":
        st.markdown(f"<p class='success'>✅ {msg}</p>", unsafe_allow_html=True)
    elif level == "warning":
        st.markdown(f"<p class='warning'>⚠️ {msg}</p>", unsafe_allow_html=True)
    elif level == "critical":
        st.markdown(f"<p class='critical'>🚨 {msg}</p>", unsafe_allow_html=True)
    else:
        st.markdown(f"ℹ️ {msg}")

def automated_response(ip, attack):
    log_event(f"[{current_time()}] Threat detected: {attack} from {ip}", "critical")
    log_event("Blocking IP in firewall...", "warning")
    time.sleep(0.5)
    log_event("Quarantining affected device...", "warning")
    time.sleep(0.5)
    log_event("Alert sent to Security Team", "info")
    log_event("Threat neutralized successfully!", "success")

def sandbox_analysis(file_name, delay):
    log_event(f"Sending {file_name} to sandbox for analysis...", "info")
    time.sleep(delay)
    verdict = random.choice(["MALICIOUS", "CLEAN"])
    if verdict == "MALICIOUS":
        log_event(f"Sandbox verdict: {verdict}", "critical")
    else:
        log_event(f"Sandbox verdict: {verdict}", "success")
    return verdict

def simulate_threat(ip, sandbox_delay):
    attack = random.choice(attack_types)
    log_event(f"Simulating: {attack} from IP {ip}", "info")
    time.sleep(0.5)

    if ip in known_bad_ips:
        log_event(f"IP matched Threat Intelligence DB: {known_bad_ips[ip]}", "critical")
        automated_response(ip, attack)
    else:
        if random.random() > 0.5:
            if attack in ["Malware Injection", "Ransomware"]:
                verdict = sandbox_analysis(f"file_{random.randint(100,999)}.exe", sandbox_delay)
                if verdict == "MALICIOUS":
                    automated_response(ip, attack)
                else:
                    log_event("No action needed. File is safe.", "success")
            else:
                automated_response(ip, attack)
        else:
            log_event("No malicious activity detected.", "success")

st.sidebar.title("⚙️ Simulation Settings")
ip_input = st.sidebar.text_input("Enter IP addresses (comma-separated) or leave blank for random")
if ip_input:
    ip_list = [ip.strip() for ip in ip_input.split(",")]
else:
    ip_list = [f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(5)]

num_runs = st.sidebar.number_input("Number of simulations", min_value=1, value=len(ip_list))
new_threat = st.sidebar.text_input("Add known bad IP (format: IP=Description) or leave blank")
if "=" in new_threat:
    ip, desc = new_threat.split("=")
    known_bad_ips[ip.strip()] = desc.strip()

sandbox_delay = st.sidebar.slider("Sandbox analysis delay (seconds)", 1, 5, 2)

st.title("🛡 CyberSecGuard – Threat Simulation & Response Dashboard")
st.markdown("A simulation platform for testing threat detection and automated response mechanisms.")

if st.button("🚀 Run Simulation"):
    st.markdown("---")
    log_event("Simulation Started...", "info")
    for i in range(num_runs):
        ip = ip_list[i % len(ip_list)]
        simulate_threat(ip, sandbox_delay)
        time.sleep(0.5)
    log_event("Simulation Completed.", "success")
