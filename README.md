# Automated SOC Alerting Platform (Mini‑SOAR)

## Overview

This project is a **Security Operations Center (SOC) Automation Platform** designed to detect, enrich, score, and alert on potential security incidents automatically.

The system simulates how modern SOC teams process security events:

Logs → Detection → Threat Intelligence Enrichment → ML Risk Scoring → Alerting

The goal of the project is to demonstrate how **security automation and orchestration (SOAR)** can reduce analyst workload by automatically analyzing suspicious activity and sending actionable alerts.

---

## Key Features

### 1. Log Parsing

Security logs are ingested and parsed to extract key indicators such as:

* Source IP
* Event type
* Timestamp
* Username

Module:

```
enrichment/log_parser.py
```

---

### 2. Brute Force Detection

The platform detects suspicious authentication patterns such as:

* Multiple failed login attempts
* Login attempts from the same IP within a short timeframe

Module:

```
detection/brute_force_detector.py
```

This simulates how SOC detection rules identify **brute force attacks**.

---

### 3. Threat Intelligence Enrichment

Once a suspicious IP is detected, the system enriches the alert with additional intelligence.

#### GeoIP Enrichment

Determines the geographic origin of the IP.

Module:

```
enrichment/geoip.py
```

Provides information such as:

* Country
* City

#### VirusTotal Lookup

Checks the IP or indicator against threat intelligence sources.

Module:

```
enrichment/virustotal.py
```

This helps determine whether the IP has been previously associated with malicious activity.

---

### 4. Machine Learning Risk Scoring

A simple ML model analyzes features from the incident to calculate a **risk score**.

Modules:

```
ml/train_model.py
ml/predict.py
```

The ML pipeline:

1. Generate training data
2. Train a model
3. Predict threat score for new incidents

Output example:

```
Threat Score: 0.92
```

---

### 5. Automated Alerting

Once the system evaluates the incident, an alert can be sent to messaging platforms such as Slack.

Alerts contain:

* Attack type
* Source IP
* Geo location
* Threat intelligence results
* ML risk score

Example alert:

```
ALERT: Brute Force Attack Detected
IP: 185.220.101.5
Country: Russia
Threat Score: 0.92
```

---

## Architecture

```
Log Source
    ↓
Log Parser
    ↓
Detection Engine
    ↓
Threat Intelligence Enrichment
    ↓
Machine Learning Risk Scoring
    ↓
Alerting System
```

This pipeline mimics the workflow of modern SOC automation platforms.

---

## Project Structure

```
soc-platform
│
├── detection
│   └── brute_force_detector.py
│
├── enrichment
│   ├── geoip.py
│   ├── log_parser.py
│   └── virustotal.py
│
├── ml
│   ├── generate_training_data.py
│   ├── train_model.py
│   └── predict.py
│
├── brute_force_detector.py
├── .gitignore
└── README.md
```

---

## Installation

Clone the repository:

```
git clone https://github.com/your-repo/soc-platform.git
cd soc-platform
```

Create a virtual environment:

```
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

---

## Environment Variables

Create a `.env` file in the root directory:

```
SLACK_TOKEN=your_slack_token
VIRUSTOTAL_API_KEY=your_api_key
```

Never commit the `.env` file to Git.

---

## How to Run

Example workflow:

1. Generate training data

```
python ml/generate_training_data.py
```

2. Train the ML model

```
python ml/train_model.py
```

3. Run the detection engine

```
python brute_force_detector.py
```

---

## Example Use Case

1. Attacker attempts multiple failed logins
2. Detection engine identifies brute force behavior
3. IP address is enriched with GeoIP and threat intelligence
4. ML model calculates a risk score
5. Alert is generated for the SOC analyst

---

## Learning Objectives

This project demonstrates:

* SOC automation concepts
* Threat intelligence integration
* Security log analysis
* Basic machine learning for security
* Incident alerting pipelines

---

## Future Improvements

Possible extensions:

* Integration with ELK Stack
* Real-time log streaming
* Dashboard for incidents
* MITRE ATT&CK mapping
* Automated response playbooks

---

## Author

Final Year Cybersecurity Project

Automated SOC Alerting Platform
