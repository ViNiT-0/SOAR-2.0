import requests
from datetime import datetime, timezone
import time

ELASTICSEARCH_URL = "http://localhost:9200"
ALERT_INDEX = "soc-alerts"
LOG_INDEX = "soc-logs-*"
THRESHOLD = 3
CHECK_INTERVAL = 60

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

def create_alert(hit_count, sample_logs):
    alert = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": "brute_force",
        "severity": "HIGH" if hit_count > 10 else "MEDIUM",
        "message": f"Brute force detected: {hit_count} failed login attempts in last 60 seconds",
        "hit_count": hit_count,
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
            print(f"[ALERT CREATED] {alert['severity']} - {alert['message']}")
            return True
    except Exception as e:
        print(f"[ERROR] Could not create alert: {e}")
    return False

def run_detector():
    print("[SOC DETECTOR] Starting brute force detection...")
    print(f"[SOC DETECTOR] Checking every {CHECK_INTERVAL} seconds")
    print(f"[SOC DETECTOR] Threshold: {THRESHOLD} failed logins in 60s")
    print("-" * 50)

    while True:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{now}] Running detection check...")

        result = check_brute_force()

        if result is None:
            print(f"[{now}] Skipping — could not reach Elasticsearch")
        elif "hits" not in result:
            print(f"[{now}] Unexpected response: {result.get('error', {}).get('reason', 'unknown error')}")
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
