import requests
import sys
import os
import time
from datetime import datetime, timezone
from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from enrichment.virustotal import check_ip_reputation, format_vt_summary
from enrichment.log_parser import extract_ip_from_logs, extract_username_from_logs
from enrichment.geoip import get_location, format_location

ELASTICSEARCH_URL = "http://localhost:9200"
ALERT_INDEX = "soc-alerts"
LOG_INDEX = "soc-logs-*"
THRESHOLD = 3
CHECK_INTERVAL = 60

load_dotenv()
SLACK_TOKEN = os.getenv("SLACK_TOKEN")
SLACK_CHANNEL = "#soc-alerts"

def check_brute_force():
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"message": "incorrect password"}},
                    {"range": {"@timestamp": {"gte": "now-60s"}}}
                ]
            }
        },
        "size": 10,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    try:
        response = requests.post(
            f"{ELASTICSEARCH_URL}/{LOG_INDEX}/_search",
            headers={"Content-Type": "application/json"},
            json=query
        )
        return response.json()
    except Exception as e:
        print(f"[ERROR] Could not query Elasticsearch: {e}")
        return None

def send_slack_alert(hit_count, severity, sample_logs, vt_result, attacker_ip, username, geo_result=None):
    color = "#ff0000" if severity == "HIGH" else "#ff9900"
    emoji = "🔴" if severity == "HIGH" else "🟠"

    if vt_result and not vt_result.get("error"):
        vt_text = (
            f"{vt_result['verdict']} — "
            f"{vt_result['malicious_engines']}/{vt_result['total_engines']} engines | "
            f"ISP: {vt_result['isp']}"
        )
        risk_score = str(vt_result['risk_score'])
    else:
        vt_text = "Could not retrieve VT data"
        risk_score = "N/A"

    location_text = format_location(geo_result) if geo_result else "Unknown"

    message = {
        "channel": SLACK_CHANNEL,
        "text": f"{emoji} *{severity} ALERT — Brute Force Detected*",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {
                        "title": "Attack Type",
                        "value": "SSH Brute Force",
                        "short": True
                    },
                    {
                        "title": "Failed Attempts",
                        "value": str(hit_count),
                        "short": True
                    },
                    {
                        "title": "Attacker IP",
                        "value": attacker_ip if attacker_ip else "Unknown",
                        "short": True
                    },
                    {
                        "title": "Target User",
                        "value": username,
                        "short": True
                    },
                    {
                        "title": "🌍 Location",
                        "value": location_text,
                        "short": True
                    },
                    {
                        "title": "Severity",
                        "value": severity,
                        "short": True
                    },
                    {
                        "title": "Time",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "short": True
                    },
                    {
                        "title": "🦠 VirusTotal Verdict",
                        "value": vt_text,
                        "short": False
                    },
                    {
                        "title": "🎯 IP Risk Score",
                        "value": risk_score,
                        "short": True
                    },
                    {
                        "title": "Sample Log",
                        "value": sample_logs[0] if sample_logs else "N/A",
                        "short": False
                    }
                ],
                "footer": "SOC Alert Platform"
            }
        ]
    }

    try:
        response = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {SLACK_TOKEN}",
                "Content-Type": "application/json"
            },
            json=message
        )
        result = response.json()
        if result.get("ok"):
            print(f"[SLACK] Alert sent to {SLACK_CHANNEL} ✅")
        else:
            print(f"[SLACK ERROR] {result.get('error')}")
    except Exception as e:
        print(f"[SLACK ERROR] {e}")

def create_alert(hit_count, sample_logs):
    severity = "HIGH" if hit_count > 10 else "MEDIUM"

    attacker_ip = extract_ip_from_logs(sample_logs)
    username = extract_username_from_logs(sample_logs)

    print(f"[ENRICHMENT] Attacker IP: {attacker_ip}")
    print(f"[ENRICHMENT] Target user: {username}")

    # VirusTotal check
    vt_result = None
    if attacker_ip:
        print(f"[ENRICHMENT] Checking VirusTotal for {attacker_ip}...")
        vt_result = check_ip_reputation(attacker_ip)
        print(f"[ENRICHMENT] VT Verdict: {vt_result['verdict']}")
    else:
        print("[ENRICHMENT] No external IP found — skipping VT check")

    # GeoIP lookup
    geo_result = None
    if attacker_ip:
        print(f"[ENRICHMENT] GeoIP lookup for {attacker_ip}...")
        geo_result = get_location(attacker_ip)
        print(f"[ENRICHMENT] Location: {format_location(geo_result)}")

    # Store alert in Elasticsearch
    alert = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": "brute_force",
        "severity": severity,
        "message": f"Brute force detected: {hit_count} failed login attempts in last 60 seconds",
        "hit_count": hit_count,
        "attacker_ip": attacker_ip,
        "target_user": username,
        "vt_verdict": vt_result["verdict"] if vt_result else "unknown",
        "vt_risk_score": vt_result["risk_score"] if vt_result else 0.0,
        "vt_country": vt_result["country"] if vt_result else "unknown",
        "geo_city": geo_result["city"] if geo_result else "unknown",
        "geo_country": geo_result["country"] if geo_result else "unknown",
        "geo_risk_score": geo_result["geo_risk_score"] if geo_result else 0.5,
        "status": "open",
        "sample_logs": sample_logs[:3]
    }

    try:
        response = requests.post(
            f"{ELASTICSEARCH_URL}/{ALERT_INDEX}/_doc",
            headers={"Content-Type": "application/json"},
            json=alert
        )
        if response.status_code == 201:
            print(f"[ALERT CREATED] {severity} - {alert['message']}")
            send_slack_alert(hit_count, severity, sample_logs, vt_result, attacker_ip, username, geo_result)
            return True
    except Exception as e:
        print(f"[ERROR] Could not create alert: {e}")
    return False

def run_detector():
    print("[SOC DETECTOR] Starting brute force detection...")
    print(f"[SOC DETECTOR] Checking every {CHECK_INTERVAL} seconds")
    print(f"[SOC DETECTOR] Threshold: {THRESHOLD} failed logins in 60s")
    print(f"[SOC DETECTOR] Slack alerts → {SLACK_CHANNEL}")
    print(f"[SOC DETECTOR] VirusTotal enrichment → enabled")
    print(f"[SOC DETECTOR] GeoIP enrichment → enabled")
    print("-" * 50)

    while True:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{now}] Running detection check...")

        result = check_brute_force()

        if result is None:
            print(f"[{now}] Skipping — could not reach Elasticsearch")
        elif "hits" not in result:
            print(f"[{now}] Unexpected response: {result.get('error', {}).get('reason', 'unknown')}")
        else:
            hit_count = result["hits"]["total"]["value"]
            print(f"[{now}] Failed logins in last 60s: {hit_count}")

            if hit_count > THRESHOLD:
                sample_logs = [
                    hit["_source"].get("message", "")
                    for hit in result["hits"]["hits"]
                ]
                create_alert(hit_count, sample_logs)
            else:
                print(f"[{now}] No threat detected. ({hit_count}/{THRESHOLD} threshold)")

        print("-" * 50)
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    run_detector()
