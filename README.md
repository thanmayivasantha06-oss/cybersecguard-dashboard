
# 🛡 CyberSecGuard – Threat Simulation & Response Dashboard

CyberSecGuard is a **Streamlit-based interactive cybersecurity web application** that simulates cyberattacks and demonstrates automated incident response mechanisms.  
It is designed for **learning, awareness, and SOC (Security Operations Center) training demos**.

---

## 🚀 Features

- **Threat Simulation**
  - Simulates 6 major attacks: Phishing, Malware, DDoS, Ransomware, Port Scanning, Brute Force.
  - Random or **Rule-based detection** mode.
- **Threat Intelligence Database**
  - Includes default bad IPs (Phishing Server, Malware C2, DDoS Botnet).
  - Add new bad IPs dynamically from the sidebar.
- **Automated Response**
  - Detect → Block IP → Quarantine Device → Alert SOC Team.
- **Real Alerts**
  - 📧 Email notifications (via SMTP/App Passwords).
  - 💬 Slack (or webhook) alerts.
- **Sandbox Analysis**
  - Suspicious files analyzed with randomized verdicts (MALICIOUS / CLEAN).
- **File Logging**
  - All alerts saved in `logs/alerts.log`.
  - Downloadable from the sidebar.
- **Customizable UI**
  - Dark theme, real-time logs, easy sidebar configuration.

---

## 🛠️ Tech Stack

- **Python 3.9+**
- **Streamlit** (UI)
- **Requests** (Slack/Webhook)
- **smtplib/email** (Email alerts)
- **OS/File I/O** (Logging)

---

## 📦 Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/your-username/cybersecguard-dashboard.git
cd cybersecguard-dashboard
pip install -r requirements.txt
```

---

## ▶️ Usage

Run the Streamlit app:

```bash
streamlit run cybersecguard_dashboard.py
```

It will open at: [http://localhost:8501](http://localhost:8501)

---

## ⚙️ Configuration

### Sidebar Controls
- Add IP addresses manually (comma-separated) or leave blank for random.
- Choose **Number of simulations**.
- Select **Detection Mode**: Random / Rule-based.
- Adjust **Sandbox delay**.

### Alerts
- **Email Alerts**: Fill in SMTP, sender, app password, recipient.  
  > Example (Gmail): SMTP Host = `smtp.gmail.com`, Port = `587`
- **Slack Alerts**: Paste Incoming Webhook URL.

### Logs
- Alerts saved in `logs/alerts.log`.
- Download button available in sidebar.

---

## 📖 Example

**Dashboard View:**  
- Shows simulated attacks in real-time.
- Logs with ✅ Success, ⚠️ Warning, 🚨 Critical.

**Alerts:**  
- Email/Slack notifications sent to SOC team.
- Logs permanently stored.

---

## 🎯 Use Cases

- Cybersecurity **education & training**.
- SOC analyst **incident response practice**.
- Awareness demos in **seminars/workshops**.
- Prototype SOC dashboard for **automation showcase**.

---

## 📌 Future Enhancements

- Charts for attack frequency & trends.  
- Multi-user authentication.  
- Integration with real Threat Intelligence feeds (AbuseIPDB, OTX).  
- Export PDF/CSV incident reports.

---

## 👩‍💻 Author
Developed by **[Your Name]**  
Part of **Cybersecurity Fundamentals, Cloud Security, Network Security, Security Operations Training**.

