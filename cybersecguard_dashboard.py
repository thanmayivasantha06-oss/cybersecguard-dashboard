
import streamlit as st
import random
import time
from datetime import datetime
import os
import smtplib
from email.mime.text import MIMEText
import requests

# -------------------------------
# Page setup & basic styling
# -------------------------------
st.set_page_config(page_title="CyberSecGuard Dashboard", layout="wide")

st.markdown(
    """
    <style>
    body { background: #0e1117; color: #e5e7eb; }
    .stButton>button {
        background-color: #FF4B4B !important;
        color: white !important;
        border-radius: 10px !important;
        height: 3em !important;
        width: 100% !important;
        font-weight: 600 !important;
    }
    .success {color: #10b981; font-weight: bold;}
    .warning {color: #f59e0b; font-weight: bold;}
    .critical {color: #ef4444; font-weight: bold;}
    .info {color: #93c5fd; font-weight: bold;}
    .small {font-size: 0.85rem; opacity: 0.9;}
    </style>
    """,
    unsafe_allow_html=True,
)

# -------------------------------
# Threat Intel & attack catalog
# -------------------------------
DEFAULT_BAD_IPS = {
    "192.168.10.45": "Malware Command & Control",
    "203.0.113.99": "Phishing Server",
    "45.67.89.101": "DDoS Botnet Node",
}

ATTACK_TYPES = [
    "Phishing Email",
    "Malware Injection",
    "DDoS Attack",
    "Ransomware",
    "Port Scanning",
    "Brute Force Login",
]

# -------------------------------
# Helpers
# -------------------------------
def current_time() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_event(msg: str, level: str = "info"):
    if level == "success":
        st.markdown(f"<p class='success'>✅ {msg}</p>", unsafe_allow_html=True)
    elif level == "warning":
        st.markdown(f"<p class='warning'>⚠️ {msg}</p>", unsafe_allow_html=True)
    elif level == "critical":
        st.markdown(f"<p class='critical'>🚨 {msg}</p>", unsafe_allow_html=True)
    else:
        st.markdown(f"<p class='info'>ℹ️ {msg}</p>", unsafe_allow_html=True)

def save_alert_to_file(ip: str, attack: str, status: str = "Blocked & Neutralized"):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "alerts.log")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{current_time()}] ALERT - Attack: {attack} | Source IP: {ip} | Status: {status}\n")
    return log_file

# -------------------------------
# Alerting: Email & Slack
# -------------------------------
def send_email_alert(ip: str, attack: str, sender: str, password: str, recipient: str, smtp_host: str, smtp_port: int):
    """Send an email alert. Uses STARTTLS."""
    if not (sender and password and recipient and smtp_host and smtp_port):
        log_event("Email settings incomplete; skipped email alert.", "warning")
        return

    subject = "🚨 CyberSecGuard Alert"
    body = f"""
Threat detected by CyberSecGuard!
---------------------------------
Attack Type: {attack}
Source IP: {ip}
Time: {current_time()}
Status: Blocked & Neutralized ✅
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, [recipient], msg.as_string())
        log_event("📧 Email alert sent to Security Team", "info")
    except Exception as e:
        log_event(f"Failed to send email alert: {e}", "warning")

def send_slack_alert(ip: str, attack: str, webhook_url: str):
    """Send a Slack (or compatible webhook) alert."""
    if not webhook_url:
        log_event("Slack webhook missing; skipped Slack alert.", "warning")
        return

    payload = {
        "text": (
            "🚨 *CyberSecGuard Alert* 🚨\n"
            f"• *Attack Type:* {attack}\n"
            f"• *Source IP:* {ip}\n"
            f"• *Time:* {current_time()}\n"
            "• *Status:* Blocked & Neutralized ✅"
        )
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code == 200:
            log_event("💬 Slack alert sent to Security Team", "info")
        else:
            log_event(f"Slack alert failed: {resp.status_code} {resp.text}", "warning")
    except Exception as e:
        log_event(f"Slack alert error: {e}", "warning")

# -------------------------------
# Sandbox analysis (simulated)
# -------------------------------
def sandbox_analysis(file_name: str, delay: float):
    log_event(f"Sending {file_name} to sandbox for analysis...", "info")
    time.sleep(delay)
    verdict = random.choice(["MALICIOUS", "CLEAN"])
    if verdict == "MALICIOUS":
        log_event(f"Sandbox verdict: {verdict}", "critical")
    else:
        log_event(f"Sandbox verdict: {verdict}", "success")
    return verdict

# -------------------------------
# Detection logic
# -------------------------------
def choose_attack_for_ip(ip: str, mode: str = "Random"):
    """Choose an attack type. Random or simple rule-based demo."""
    if mode == "Rule-based":
        # Very simple deterministic mapping to illustrate rules (demo only)
        try:
            octets = [int(x) for x in ip.split(".")]
        except Exception:
            # If IP isn't parseable, fall back to random
            return random.choice(ATTACK_TYPES)

        o1, o2, o3, o4 = (octets + [0, 0, 0, 0])[:4]

        # Example heuristic demo rules
        if o4 % 7 == 0:
            return "DDoS Attack"
        if o1 in (10, 172, 192) and o2 in (0, 16, 168):
            return "Port Scanning"
        if "23" in ip:
            return "Malware Injection"
        if o4 % 5 == 0:
            return "Brute Force Login"
        if o1 > 200:
            return "Phishing Email"
        return "Ransomware"
    else:
        return random.choice(ATTACK_TYPES)

def simulate_threat(ip: str, sandbox_delay: float, detection_mode: str):
    attack = choose_attack_for_ip(ip, detection_mode)
    log_event(f"Simulating: {attack} from IP {ip}", "info")
    time.sleep(0.3)

    # Known bad IPs = instant malicious
    if ip in st.session_state.known_bad_ips:
        log_event(f"IP matched Threat Intelligence DB: {st.session_state.known_bad_ips[ip]}", "critical")
        automated_response(ip, attack)
        return

    # Unknown IPs:
    # Random probability of detection for demo realism
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

# -------------------------------
# Automated response
# -------------------------------
def automated_response(ip: str, attack: str):
    log_event(f"[{current_time()}] Threat detected: {attack} from {ip}", "critical")
    log_event("Blocking IP in firewall...", "warning")
    time.sleep(0.4)
    log_event("Quarantining affected device...", "warning")
    time.sleep(0.4)

    # Send alerts based on user settings
    if st.session_state.enable_email:
        send_email_alert(
            ip=ip,
            attack=attack,
            sender=st.session_state.email_sender,
            password=st.session_state.email_password,
            recipient=st.session_state.email_recipient,
            smtp_host=st.session_state.smtp_host,
            smtp_port=int(st.session_state.smtp_port or 587),
        )

    if st.session_state.enable_slack:
        send_slack_alert(ip=ip, attack=attack, webhook_url=st.session_state.slack_webhook)

    # Persist alert to file
    log_path = save_alert_to_file(ip, attack)
    st.session_state.last_log_path = log_path

    log_event("Threat neutralized successfully!", "success")

# -------------------------------
# Session state init
# -------------------------------
if "known_bad_ips" not in st.session_state:
    st.session_state.known_bad_ips = DEFAULT_BAD_IPS.copy()

for key, default in [
    ("enable_email", False),
    ("email_sender", ""),
    ("email_password", ""),
    ("email_recipient", ""),
    ("smtp_host", "smtp.gmail.com"),
    ("smtp_port", "587"),
    ("enable_slack", False),
    ("slack_webhook", ""),
    ("last_log_path", ""),
]:
    st.session_state.setdefault(key, default)

# -------------------------------
# Sidebar controls
# -------------------------------
st.sidebar.title("⚙️ Simulation Settings")

ip_input = st.sidebar.text_input("Enter IP addresses (comma-separated) or leave blank for random")
if ip_input.strip():
    ip_list = [ip.strip() for ip in ip_input.split(",") if ip.strip()]
else:
    ip_list = [f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(5)]

num_runs = st.sidebar.number_input("Number of simulations", min_value=1, value=max(1, len(ip_list)))

# Add new bad IPs dynamically
new_threat = st.sidebar.text_input("Add known bad IP (format: IP=Description)")
if "=" in new_threat:
    ip, desc = new_threat.split("=", 1)
    st.session_state.known_bad_ips[ip.strip()] = desc.strip()
    st.sidebar.success(f"Added {ip.strip()} ➜ {desc.strip()}")

sandbox_delay = st.sidebar.slider("Sandbox analysis delay (seconds)", 1, 5, 2)

detection_mode = st.sidebar.radio("Detection Mode", ["Random", "Rule-based"], index=0, horizontal=True)

st.sidebar.markdown("---")
st.sidebar.subheader("📧 Email Alerts")
st.session_state.enable_email = st.sidebar.checkbox("Enable Email Alerts", value=st.session_state.enable_email)
st.session_state.email_sender = st.sidebar.text_input("Sender Email", value=st.session_state.email_sender, help="Use an app password for Gmail.")
st.session_state.email_password = st.sidebar.text_input("Email Password / App Password", type="password", value=st.session_state.email_password)
st.session_state.email_recipient = st.sidebar.text_input("Recipient Email", value=st.session_state.email_recipient)
st.session_state.smtp_host = st.sidebar.text_input("SMTP Host", value=st.session_state.smtp_host)
st.session_state.smtp_port = st.sidebar.text_input("SMTP Port", value=st.session_state.smtp_port)

st.sidebar.markdown("---")
st.sidebar.subheader("💬 Slack Alerts")
st.session_state.enable_slack = st.sidebar.checkbox("Enable Slack/Webhook Alerts", value=st.session_state.enable_slack)
st.session_state.slack_webhook = st.sidebar.text_input("Webhook URL", value=st.session_state.slack_webhook, help="Slack Incoming Webhook or compatible URL")

st.sidebar.markdown("---")
st.sidebar.subheader("🗂️ Logs")
if st.session_state.get("last_log_path"):
    try:
        with open(st.session_state.last_log_path, "rb") as f:
            st.sidebar.download_button("Download alerts.log", f, file_name="alerts.log")
    except FileNotFoundError:
        pass

# -------------------------------
# Main UI
# -------------------------------
st.title("🛡 CyberSecGuard – Threat Simulation & Response Dashboard")
st.markdown("A simulation platform for testing **threat detection** and **automated response** mechanisms.")

# Show current Threat Intel table
with st.expander("📚 Current Threat Intelligence (Known Bad IPs)"):
    if st.session_state.known_bad_ips:
        for ip, desc in st.session_state.known_bad_ips.items():
            st.markdown(f"- **{ip}** — {desc}")
    else:
        st.write("No known bad IPs. Add some from the sidebar.")

st.markdown("---")

if st.button("🚀 Run Simulation"):
    st.markdown("---")
    log_event("Simulation Started...", "info")
    for i in range(int(num_runs)):
        ip = ip_list[i % len(ip_list)]
        simulate_threat(ip, sandbox_delay, detection_mode)
        time.sleep(0.3)
    log_event("Simulation Completed.", "success")
    st.caption("Tip: Configure Email/Slack in the sidebar to send real alerts. Download the `alerts.log` from the sidebar.")
