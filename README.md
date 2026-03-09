# 🛡️ Automated SOC Alerting Platform
### Final Year Bachelor's Project — Cybersecurity

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.13-yellow)
![Docker](https://img.shields.io/badge/Docker-27.5-blue)
![Slack](https://img.shields.io/badge/Slack-API-purple)
![ML](https://img.shields.io/badge/ML-RandomForest-green)
![Status](https://img.shields.io/badge/Status-In%20Progress-orange)

---

## 📌 What Is This Project?

This is a **real-time Security Operations Center (SOC) platform** that automatically detects, enriches, and alerts on cybersecurity threats — with zero human intervention.

Most organizations receive thousands of security alerts per day. Analysts cannot review them all manually, leading to **alert fatigue** — where real threats get missed because analysts are overwhelmed by noise.

This platform solves that by:
1. **Automatically detecting** brute force attacks and suspicious login activity
2. **Enriching alerts** with threat intelligence (VirusTotal, GeoIP)
3. **Scoring each alert** with an AI model to predict if it's a real threat or false positive
4. **Sending formatted alerts** to Slack with full context for the analyst

---

## 🎯 Key Innovation — AI False Positive Prediction

> **The biggest problem in SOC work is that 90%+ of alerts are false positives.**

This project includes a **lightweight Machine Learning model** (Random Forest Classifier) that scores every alert before it reaches an analyst:

```
Alert fires
    ↓
ML Model analyzes 7 features
    ↓
Returns: "72% False Positive Probability"
    ↓
If > 80% → Auto-dismiss (log it, don't page anyone)
If 40-80% → Send to Slack with LOW CONFIDENCE tag
If < 40%  → CRITICAL alert, page analyst immediately
```

**Features used by the ML model:**

| Feature | Description |
|---|---|
| `ip_reputation_score` | VirusTotal malicious vote ratio (0.0 - 1.0) |
| `historical_alert_count` | How many times this IP has triggered alerts before |
| `is_internal_ip` | Is this from inside the network? (192.168.x.x) |
| `hour_of_day` | 3AM alert is more suspicious than 9AM |
| `alert_frequency_spike` | Sudden burst vs normal baseline |
| `geo_risk_score` | High-risk country = higher threat score |
| `failed_login_ratio` | Ratio of failed vs successful logins |

**Model Performance:**
- Accuracy: **90.75%**
- Algorithm: Random Forest (100 trees)
- Training samples: 2000 (balanced true/false positives)

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    DATA SOURCES                          │
│         Linux auth.log, SSH logs, System logs            │
└──────────────────────┬──────────────────────────────────┘
                       │ Raw Logs
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  FILEBEAT (Log Shipper)                  │
│     Watches /var/log/auth.log → ships to Logstash        │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│              ELASTIC STACK (ELK)                         │
│  Logstash (parse) → Elasticsearch (store) → Kibana (UI)  │
│  Index: soc-logs-YYYY.MM.DD                              │
└──────────────────────┬──────────────────────────────────┘
                       │ Python queries every 60s
                       ▼
┌─────────────────────────────────────────────────────────┐
│           PYTHON DETECTION ENGINE                        │
│  • Detects brute force (>3 failed logins in 60s)         │
│  • Extracts attacker IP from log messages                │
│  • Calls VirusTotal API for IP reputation                │
│  • Calls GeoIP for attacker location                     │
│  • Runs ML model for False Positive score                │
└──────────────────────┬──────────────────────────────────┘
                       │
          ┌────────────┴───────────┐
          ▼                        ▼
┌──────────────────┐   ┌─────────────────────────┐
│  Elasticsearch   │   │     SLACK API            │
│  soc-alerts      │   │  Rich alert card with:   │
│  index           │   │  • Severity + emoji      │
│  (stores all     │   │  • Attacker IP           │
│   alerts for     │   │  • 🌍 GeoIP location     │
│   Kibana)        │   │  • 🦠 VT verdict         │
└──────────────────┘   │  • 🤖 AI FP score        │
                        └─────────────────────────┘
```

---

## 🔧 Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| **Log Collection** | Filebeat 8.13 | Ships auth logs to ELK |
| **Log Processing** | Logstash 8.13 | Parses and normalizes logs |
| **Storage** | Elasticsearch 8.13 | Stores all logs and alerts |
| **Dashboard** | Kibana 8.13 | Visual SOC dashboard |
| **Orchestration** | n8n | Workflow automation |
| **Detection** | Python 3.13 | Brute force detection engine |
| **Threat Intel** | VirusTotal API | IP reputation check |
| **Geolocation** | GeoLite2 (offline) | Attacker location lookup |
| **ML Model** | scikit-learn (Random Forest) | False positive prediction |
| **Alerting** | Slack API | Rich formatted alerts |
| **Infrastructure** | Docker + Docker Compose | Containerized deployment |

---

## 📁 Project Structure

```
soc-platform/
│
├── docker-compose.yml              # ELK Stack + n8n containers
│
├── elk/
│   ├── logstash/
│   │   ├── pipeline/
│   │   │   └── logstash.conf       # Log parsing rules
│   │   └── config/
│   │       └── logstash.yml        # Logstash config
│
├── detection/
│   └── brute_force_detector.py     # Main detection engine
│
├── enrichment/
│   ├── virustotal.py               # VirusTotal API integration
│   ├── geoip.py                    # GeoIP location lookup
│   └── log_parser.py               # Extract IPs/usernames from logs
│
├── ml/
│   ├── generate_training_data.py   # Synthetic training data generator
│   ├── train_model.py              # Train Random Forest model
│   ├── predict.py                  # Predict FP probability for alerts
│   ├── training_data.csv           # 2000 labeled training samples
│   └── model.pkl                   # Saved trained model
│
├── data/
│   └── GeoLite2-City.mmdb          # Offline GeoIP database (61MB)
│
└── venv/                           # Python virtual environment
```

---

## 🚀 How to Run

### Prerequisites
- Kali Linux / Ubuntu
- Docker + Docker Compose
- Python 3.x
- 4GB+ RAM, 20GB+ disk space

### 1. Start the Infrastructure
```bash
cd ~/soc-platform
docker compose up -d
```

### 2. Activate Python Environment
```bash
source venv/bin/activate
```

### 3. Start the Detection Engine
```bash
python3 detection/brute_force_detector.py
```

### 4. View the Dashboard
Open `http://localhost:5601` in your browser (Kibana)

### 5. View n8n Workflows
Open `http://localhost:5678` in your browser

---

## 📊 What a Slack Alert Looks Like

```
🔴 HIGH ALERT — Brute Force Detected
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Attack Type          Failed Attempts
SSH Brute Force      18

Attacker IP          Target User
185.220.101.45       root

🌍 Location          Severity
🇩🇪 Brandenburg, Germany    HIGH

Time
2026-03-09 16:05:18

🦠 VirusTotal Verdict
MALICIOUS — 16/94 engines | ISP: Stiftung Erneuerbare Freiheit

🎯 IP Risk Score
0.2

🤖 AI False Positive Score        [coming in Day 9]
[██░░░░░░░░░░░░░░░░░░] 10.9% — LIKELY REAL THREAT
Reason: High VT reputation, High risk country, High failure ratio

Sample Log
Failed password for root from 185.220.101.45 port 22 ssh2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SOC Alert Platform
```

---

## ✅ Current Progress

| Day | Task | Status |
|---|---|---|
| Day 1 | Docker installed | ✅ Done |
| Day 2 | ELK Stack running | ✅ Done |
| Day 3 | First logs in Kibana | ✅ Done |
| Day 4 | Filebeat auto-shipping auth.log | ✅ Done |
| Day 5 | Python brute force detection | ✅ Done |
| Day 6 | Slack alerting with rich cards | ✅ Done |
| Day 7 | VirusTotal IP enrichment | ✅ Done |
| Day 8 | GeoIP location + ML model trained | ✅ Done |
| Day 9 | ML score in Slack alerts | 🔄 In Progress |
| Day 10 | n8n workflow integration | ⏳ Pending |
| Day 11 | Full end-to-end demo | ⏳ Pending |
| Day 12 | Documentation + report | ⏳ Pending |

---

## 🧠 How the ML Model Works (For Non-Technical Readers)

Think of the ML model like an experienced SOC analyst who has seen thousands of alerts before. Over time they learn patterns:

> *"When an alert comes from an internal IP address during business hours and that IP has triggered 30 alerts before without any being real threats — it's probably nothing."*

> *"But when an alert comes at 3AM from a German IP that 16 antivirus engines flagged as malicious, with 95% of its login attempts failing — that's a real attack."*

The model learns these patterns from 2000 labeled examples and applies them to every new alert in milliseconds.

---

## 🔬 Why This Is Different From Existing Tools

| Feature | Our Platform | Commercial SIEMs |
|---|---|---|
| ML False Positive Score | ✅ Built-in, explainable | ❌ Black box or absent |
| Educational transparency | ✅ Every decision explained | ❌ Proprietary |
| Cost | ✅ 100% free/open source | ❌ $50,000+/year |
| Customizable | ✅ Full source code | ❌ Limited |
| GeoIP + VT enrichment | ✅ Automatic | ✅ Yes (paid) |

---

## 👨‍💻 Author

**Final Year Student — Bachelor of Computer Science**
Specialization: Cybersecurity
Project supervised by: [Professor Name]

---

## 📜 License

This project is built for educational purposes as a final year project.
External services used: VirusTotal API, Slack API, Elastic Stack, MaxMind GeoLite2.
