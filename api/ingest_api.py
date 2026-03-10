import sys
import os
from flask import Flask, request, jsonify
from datetime import datetime, timezone
import requests
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from enrichment.virustotal import check_ip_reputation
from enrichment.geoip import get_location, format_location
from ml.predict import predict_false_positive, format_fp_bar

app = Flask(__name__)

ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
SLACK_TOKEN       = os.getenv("SLACK_TOKEN")
SLACK_CHANNEL     = os.getenv("SLACK_CHANNEL", "#soc-alerts")
API_KEY           = os.getenv("SOC_API_KEY", "changeme123")

LOG_INDEX         = "web-logs"
ALERT_INDEX       = "soc-alerts"

# Attack pattern signatures
SQLI_PATTERNS     = ["union select", "' or 1=1", "drop table", "insert into",
                     "1=1--", "or '1'='1", "xp_cmdshell", "exec(", "0x"]
XSS_PATTERNS      = ["<script", "javascript:", "onerror=", "onload=",
                     "alert(", "document.cookie", "eval("]
TRAVERSAL_PATTERNS= ["../", "..\\", "/etc/passwd", "/etc/shadow",
                     "boot.ini", "win.ini", "/proc/self"]
PROBE_PATHS       = ["/wp-admin", "/wp-login", "/phpmyadmin", "/admin",
                     "/.env", "/.git", "/config", "/backup", "/db"]

def detect_attack_type(url, method, status_code, body=""):
    """Analyse a single request for attack signatures."""
    url_lower   = url.lower()
    body_lower  = (body or "").lower()
    combined    = url_lower + " " + body_lower

    if any(p in combined for p in SQLI_PATTERNS):
        return "sql_injection", "HIGH"
    if any(p in combined for p in XSS_PATTERNS):
        return "xss_attempt", "HIGH"
    if any(p in combined for p in TRAVERSAL_PATTERNS):
        return "path_traversal", "HIGH"
    if any(p in url_lower for p in PROBE_PATHS):
        return "admin_probe", "MEDIUM"
    if status_code == 401 and method == "POST":
        return "web_login_attempt", "LOW"
    if status_code == 404:
        return "not_found", "LOW"
    return None, None

def check_brute_force(ip, site, window="now-60s", threshold=10):
    """Check if this IP has made many failed login attempts recently."""
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"ip.keyword": ip}},
                    {"term":  {"site.keyword": site}},
                    {"term":  {"status_code": 401}},
                    {"range": {"@timestamp": {"gte": window}}}
                ]
            }
        },
        "size": 0
    }
    try:
        r = requests.post(
            f"{ELASTICSEARCH_URL}/{LOG_INDEX}/_search",
            headers={"Content-Type": "application/json"},
            json=query, timeout=5
        )
        count = r.json().get("hits", {}).get("total", {}).get("value", 0)
        return count >= threshold
    except Exception:
        return False

def check_scan_activity(ip, site, window="now-60s", threshold=20):
    """Check if this IP is making many 404 requests (scanning)."""
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {"ip.keyword": ip}},
                    {"term":  {"site.keyword": site}},
                    {"term":  {"status_code": 404}},
                    {"range": {"@timestamp": {"gte": window}}}
                ]
            }
        },
        "size": 0
    }
    try:
        r = requests.post(
            f"{ELASTICSEARCH_URL}/{LOG_INDEX}/_search",
            headers={"Content-Type": "application/json"},
            json=query, timeout=5
        )
        count = r.json().get("hits", {}).get("total", {}).get("value", 0)
        return count >= threshold, count
    except Exception:
        return False, 0

def send_slack_alert(alert_type, severity, site, ip, url,
                     geo_result, vt_result, fp_result, extra=""):
    color = {"HIGH": "#ff0000", "MEDIUM": "#ff9900", "LOW": "#36a64f"}.get(severity, "#cccccc")
    emoji = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(severity, "⚪")

    label = {
        "sql_injection":    "SQL Injection",
        "xss_attempt":      "XSS Attempt",
        "path_traversal":   "Path Traversal",
        "admin_probe":      "Admin Panel Probe",
        "web_bruteforce":   "Web Login Brute Force",
        "web_scan":         "Directory Scanning",
    }.get(alert_type, alert_type.replace("_", " ").title())

    vt_text = "N/A"
    if vt_result and not vt_result.get("error"):
        vt_text = (f"{vt_result['verdict']} — "
                   f"{vt_result['malicious_engines']}/{vt_result['total_engines']} engines | "
                   f"ISP: {vt_result['isp']}")

    fp_text = "N/A"
    if fp_result:
        fp_text = (f"{format_fp_bar(fp_result['fp_probability'])} — {fp_result['label']}\n"
                   f"Action: {fp_result['action']}")

    message = {
        "channel": SLACK_CHANNEL,
        "text": f"{emoji} *{severity} WEB ALERT — {label}*",
        "attachments": [{
            "color": color,
            "fields": [
                {"title": "Attack Type",   "value": label,                              "short": True},
                {"title": "Target Site",   "value": site,                               "short": True},
                {"title": "Attacker IP",   "value": ip,                                 "short": True},
                {"title": "Location",      "value": format_location(geo_result) if geo_result else "Unknown", "short": True},
                {"title": "Severity",      "value": severity,                           "short": True},
                {"title": "Time",          "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "short": True},
                {"title": "Suspicious URL","value": url[:200],                          "short": False},
                {"title": "🦠 VirusTotal", "value": vt_text,                            "short": False},
                {"title": "🤖 AI FP Score","value": fp_text,                            "short": False},
            ],
            "footer": "SOC Alert Platform — Web Monitor"
        }]
    }
    if extra:
        message["attachments"][0]["fields"].append(
            {"title": "Details", "value": extra, "short": False}
        )

    try:
        if not SLACK_TOKEN:
            return
        r = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {SLACK_TOKEN}",
                     "Content-Type": "application/json"},
            json=message, timeout=10
        )
        if r.json().get("ok"):
            print(f"[SLACK] Web alert sent ✅")
    except Exception as e:
        print(f"[SLACK ERROR] {e}")

def create_web_alert(alert_type, severity, site, ip, url,
                     geo_result, vt_result, fp_result, request_count=1):
    """Store alert in Elasticsearch and send to Slack."""
    alert = {
        "@timestamp":     datetime.now(timezone.utc).isoformat(),
        "alert_type":     alert_type,
        "source":         "web",
        "severity":       severity,
        "site":           site,
        "attacker_ip":    ip,
        "url":            url,
        "geo_city":       geo_result["city"] if geo_result else "unknown",
        "geo_country":    geo_result["country"] if geo_result else "unknown",
        "geo_risk_score": geo_result["geo_risk_score"] if geo_result else 0.5,
        "vt_verdict":     vt_result.get("verdict", "unknown") if vt_result else "unknown",
        "vt_risk_score":  vt_result.get("risk_score", 0.0) if vt_result else 0.0,
        "fp_probability": fp_result["fp_probability"] if fp_result else None,
        "fp_label":       fp_result["label"] if fp_result else None,
        "request_count":  request_count,
        "status":         "open"
    }
    try:
        r = requests.post(
            f"{ELASTICSEARCH_URL}/{ALERT_INDEX}/_doc",
            headers={"Content-Type": "application/json"},
            json=alert, timeout=5
        )
        if r.status_code == 201:
            print(f"[ALERT] {severity} {alert_type} on {site} from {ip}")
            send_slack_alert(alert_type, severity, site, ip, url,
                             geo_result, vt_result, fp_result)
    except Exception as e:
        print(f"[ERROR] Could not create alert: {e}")

# ─────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "SOC Ingest API", "version": "1.0"})

@app.route("/api/ingest", methods=["POST"])
def ingest():
    """
    Main ingest endpoint. Accepts a single web request log.

    Required fields:
        ip          — client IP address
        url         — request path e.g. /login
        method      — HTTP method GET/POST etc.
        status_code — HTTP response status
        site        — identifier e.g. "mysite.com"

    Optional fields:
        body        — request body (for POST payload inspection)
        user_agent  — browser/client user agent
        api_key     — authentication key
    """

    # ── Auth check ────────────────────────────────────────────
    data    = request.get_json(silent=True) or {}
    api_key = request.headers.get("X-API-Key") or data.get("api_key", "")
    if api_key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    # ── Validate required fields ──────────────────────────────
    ip          = data.get("ip", "").strip()
    url         = data.get("url", "/").strip()
    method      = data.get("method", "GET").upper()
    status_code = int(data.get("status_code", 200))
    site        = data.get("site", "unknown").strip()
    body        = data.get("body", "")
    user_agent  = data.get("user_agent", "")

    if not ip or not site:
        return jsonify({"error": "ip and site are required"}), 400

    # ── Store raw log in Elasticsearch ───────────────────────
    log_doc = {
        "@timestamp":  datetime.now(timezone.utc).isoformat(),
        "ip":          ip,
        "url":         url,
        "method":      method,
        "status_code": status_code,
        "site":        site,
        "user_agent":  user_agent,
        "source":      "web"
    }
    try:
        requests.post(
            f"{ELASTICSEARCH_URL}/{LOG_INDEX}/_doc",
            headers={"Content-Type": "application/json"},
            json=log_doc, timeout=5
        )
    except Exception as e:
        print(f"[ES ERROR] {e}")

    # ── Detect attack in this single request ─────────────────
    attack_type, severity = detect_attack_type(url, method, status_code, body)
    triggered = False

    if attack_type and attack_type not in ("web_login_attempt", "not_found"):
        # Immediate high-signal attack — enrich and alert now
        geo_result = get_location(ip)
        vt_result  = check_ip_reputation(ip) if ip else None
        fp_result  = None
        try:
            fp_result = predict_false_positive(
                ip_reputation_score    = vt_result.get("risk_score", 0.5) if vt_result else 0.5,
                historical_alert_count = 0,
                is_internal_ip         = 0,
                hour_of_day            = datetime.now().hour,
                alert_frequency_spike  = 1 if severity == "HIGH" else 0,
                geo_risk_score         = geo_result["geo_risk_score"] if geo_result else 0.5,
                failed_login_ratio     = 0.9
            )
        except Exception:
            pass

        create_web_alert(attack_type, severity, site, ip, url,
                         geo_result, vt_result, fp_result)
        triggered = True

    # ── Check cumulative patterns (brute force / scan) ───────
    elif attack_type == "web_login_attempt":
        if check_brute_force(ip, site):
            geo_result = get_location(ip)
            vt_result  = check_ip_reputation(ip) if ip else None
            fp_result  = None
            try:
                fp_result = predict_false_positive(
                    ip_reputation_score    = vt_result.get("risk_score", 0.5) if vt_result else 0.5,
                    historical_alert_count = 0,
                    is_internal_ip         = 0,
                    hour_of_day            = datetime.now().hour,
                    alert_frequency_spike  = 1,
                    geo_risk_score         = geo_result["geo_risk_score"] if geo_result else 0.5,
                    failed_login_ratio     = 0.95
                )
            except Exception:
                pass
            create_web_alert("web_bruteforce", "HIGH", site, ip, url,
                             geo_result, vt_result, fp_result)
            triggered = True

    elif attack_type == "not_found":
        is_scan, count = check_scan_activity(ip, site)
        if is_scan:
            geo_result = get_location(ip)
            vt_result  = check_ip_reputation(ip) if ip else None
            create_web_alert("web_scan", "MEDIUM", site, ip, url,
                             geo_result, vt_result, None,
                             request_count=count)
            triggered = True

    return jsonify({
        "status":    "received",
        "triggered": triggered,
        "attack":    attack_type,
        "severity":  severity
    }), 200


@app.route("/api/test", methods=["POST"])
def test_alert():
    """Send a test alert to verify the pipeline is working."""
    api_key = request.headers.get("X-API-Key", "")
    if api_key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    site = data.get("site", "test.example.com")

    geo_result = get_location("185.220.101.45")
    vt_result  = check_ip_reputation("185.220.101.45")
    try:
        fp_result = predict_false_positive(
            ip_reputation_score=0.85, historical_alert_count=1,
            is_internal_ip=0, hour_of_day=3,
            alert_frequency_spike=1, geo_risk_score=0.9,
            failed_login_ratio=0.95
        )
    except Exception:
        fp_result = None

    create_web_alert("sql_injection", "HIGH", site,
                     "185.220.101.45",
                     "/login?id=1 UNION SELECT username,password FROM users",
                     geo_result, vt_result, fp_result)

    return jsonify({"status": "test alert sent", "site": site}), 200


if __name__ == "__main__":
    print("[SOC API] Starting Web Ingest API...")
    print(f"[SOC API] Listening on http://0.0.0.0:8000")
    print(f"[SOC API] POST /api/ingest  — receive web logs")
    print(f"[SOC API] POST /api/test    — send test alert")
    print(f"[SOC API] GET  /health      — health check")
    print("-" * 50)
    app.run(host="0.0.0.0", port=8000, debug=False)
