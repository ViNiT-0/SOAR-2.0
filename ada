[1mdiff --git a/README.md b/README.md[m
[1mindex 0511205..a9238c2 100644[m
[1m--- a/README.md[m
[1m+++ b/README.md[m
[36m@@ -71,8 +71,8 @@[m [mIf < 40%  → CRITICAL alert, page analyst immediately[m
                        │ Raw Logs[m
                        ▼[m
 ┌─────────────────────────────────────────────────────────┐[m
[31m-│                  FILEBEAT (Log Shipper)                  │[m
[31m-│     Watches /var/log/auth.log → ships to Logstash        │[m
[32m+[m[32m│                FILEBEAT (Log Shipper)                    │[m
[32m+[m[32m│  Runs on the host and ships auth/system logs to Logstash │[m
 └──────────────────────┬──────────────────────────────────┘[m
                        │[m
                        ▼[m
[36m@@ -176,12 +176,24 @@[m [mcd ~/soc-platform[m
 docker compose up -d[m
 ```[m
 [m
[31m-### 2. Activate Python Environment[m
[32m+[m[32m### 2. Get Logs Into ELK (Choose One)[m
[32m+[m
[32m+[m[32m**Option A (recommended): Host Filebeat → Logstash (beats input on port 5044)**[m
[32m+[m
[32m+[m[32m- Logstash is configured for Beats input in `elk/logstash/pipeline/logstash.conf` and writes to `soc-logs-YYYY.MM.DD`.[m
[32m+[m[32m- Install and configure Filebeat on the host to ship `/var/log/auth.log` (or syslog) to `localhost:5044`.[m
[32m+[m[32m- This repo includes `filebeat-8.13.0-amd64.deb` for convenience (Kali/Ubuntu).[m
[32m+[m
[32m+[m[32m**Option B (demo): Send a test document directly to Elasticsearch**[m
[32m+[m
[32m+[m[32m- For quick demos without Filebeat, you can index a few test log lines into `soc-logs-YYYY.MM.DD` and the detector will pick them up.[m
[32m+[m
[32m+[m[32m### 3. Activate Python Environment[m
 ```bash[m
 source venv/bin/activate[m
 ```[m
 [m
[31m-### 3. Start the Detection Engine[m
[32m+[m[32m### 4. Start the Detection Engine[m
 ```bash[m
 python3 detection/brute_force_detector.py[m
 ```[m
[36m@@ -227,6 +239,8 @@[m [mFailed password for root from 185.220.101.45 port 22 ssh2[m
 SOC Alert Platform[m
 ```[m
 [m
[32m+[m[32m> Note: ML scoring is included in the detector. If `ml/model.pkl` is missing, the detector will skip FP scoring and still alert normally.[m
[32m+[m
 [m
 [m
 ## How the ML Model Works (For Non-Technical Readers)[m
[1mdiff --git a/detection/brute_force_detector.py b/detection/brute_force_detector.py[m
[1mindex a102b8f..5327a41 100644[m
[1m--- a/detection/brute_force_detector.py[m
[1m+++ b/detection/brute_force_detector.py[m
[36m@@ -10,6 +10,7 @@[m [msys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))[m
 from enrichment.virustotal import check_ip_reputation, format_vt_summary[m
 from enrichment.log_parser import extract_ip_from_logs, extract_username_from_logs[m
 from enrichment.geoip import get_location, format_location[m
[32m+[m[32mfrom ml.predict import predict_false_positive, format_fp_bar[m
 [m
 load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))[m
 [m
[36m@@ -24,6 +25,33 @@[m [mSLACK_CHANNEL = os.getenv("SLACK_CHANNEL", "#soc-alerts")[m
 [m
 HTTP_TIMEOUT_S = 10[m
 [m
[32m+[m[32mdef get_historical_alert_count(attacker_ip: str) -> int:[m
[32m+[m[32m    if not attacker_ip:[m
[32m+[m[32m        return 0[m
[32m+[m[32m    query = {[m
[32m+[m[32m        "query": {[m
[32m+[m[32m            "bool": {[m
[32m+[m[32m                "filter": [[m
[32m+[m[32m                    {"term": {"attacker_ip.keyword": attacker_ip}},[m
[32m+[m[32m                    {"range": {"@timestamp": {"gte": "now-30d"}}}[m
[32m+[m[32m                ][m
[32m+[m[32m            }[m
[32m+[m[32m        },[m
[32m+[m[32m        "size": 0[m
[32m+[m[32m    }[m
[32m+[m[32m    try:[m
[32m+[m[32m        response = requests.post([m
[32m+[m[32m            f"{ELASTICSEARCH_URL}/{ALERT_INDEX}/_search",[m
[32m+[m[32m            headers={"Content-Type": "application/json"},[m
[32m+[m[32m            json=query,[m
[32m+[m[32m            timeout=HTTP_TIMEOUT_S[m
[32m+[m[32m        )[m
[32m+[m[32m        data = response.json()[m
[32m+[m[32m        return int(data.get("hits", {}).get("total", {}).get("value", 0))[m
[32m+[m[32m    except Exception as e:[m
[32m+[m[32m        print(f"[ERROR] Could not query historical alerts: {e}")[m
[32m+[m[32m        return 0[m
[32m+[m
 def check_brute_force():[m
     query = {[m
         "query": {[m
[36m@@ -51,7 +79,7 @@[m [mdef check_brute_force():[m
         print(f"[ERROR] Could not query Elasticsearch: {e}")[m
         return None[m
 [m
[31m-def send_slack_alert(hit_count, severity, sample_logs, vt_result, attacker_ip, username, geo_result=None):[m
[32m+[m[32mdef send_slack_alert(hit_count, severity, sample_logs, vt_result, attacker_ip, username, geo_result=None, fp_result=None):[m
     color = "#ff0000" if severity == "HIGH" else "#ff9900"[m
     emoji = "🔴" if severity == "HIGH" else "🟠"[m
 [m
[36m@@ -68,6 +96,14 @@[m [mdef send_slack_alert(hit_count, severity, sample_logs, vt_result, attacker_ip, u[m
 [m
     location_text = format_location(geo_result) if geo_result else "Unknown"[m
 [m
[32m+[m[32m    fp_text = "N/A"[m
[32m+[m[32m    fp_reasons = "N/A"[m
[32m+[m[32m    fp_action = "N/A"[m
[32m+[m[32m    if fp_result:[m
[32m+[m[32m        fp_text = f"{format_fp_bar(fp_result['fp_probability'])} — {fp_result['label']}"[m
[32m+[m[32m        fp_action = fp_result.get("action", "N/A")[m
[32m+[m[32m        fp_reasons = ", ".join(fp_result.get("reasons", [])) or "N/A"[m
[32m+[m
     message = {[m
         "channel": SLACK_CHANNEL,[m
         "text": f"{emoji} *{severity} ALERT — Brute Force Detected*",[m
[36m@@ -120,6 +156,21 @@[m [mdef send_slack_alert(hit_count, severity, sample_logs, vt_result, attacker_ip, u[m
                         "value": risk_score,[m
                         "short": True[m
                     },[m
[32m+[m[32m                    {[m
[32m+[m[32m                        "title": "🤖 AI False Positive Score",[m
[32m+[m[32m                        "value": fp_text,[m
[32m+[m[32m                        "short": False[m
[32m+[m[32m                    },[m
[32m+[m[32m                    {[m
[32m+[m[32m                        "title": "Recommended Action",[m
[32m+[m[32m                        "value": fp_action,[m
[32m+[m[32m                        "short": True[m
[32m+[m[32m                    },[m
[32m+[m[32m                    {[m
[32m+[m[32m                        "title": "AI Reasons",[m
[32m+[m[32m                        "value": fp_reasons,[m
[32m+[m[32m                        "short": False[m
[32m+[m[32m                    },[m
                     {[m
                         "title": "Sample Log",[m
                         "value": sample_logs[0] if sample_logs else "N/A",[m
[36m@@ -186,6 +237,31 @@[m [mdef create_alert(hit_count, sample_logs):[m
         geo_result = get_location(attacker_ip)[m
         print(f"[ENRICHMENT] Location: {format_location(geo_result)}")[m
 [m
[32m+[m[32m    # ML false-positive scoring[m
[32m+[m[32m    fp_result = None[m
[32m+[m[32m    try:[m
[32m+[m[32m        hour_of_day = datetime.now().hour[m
[32m+[m[32m        is_internal_ip = 0[m
[32m+[m[32m        try:[m
[32m+[m[32m            is_internal_ip = 0 if (attacker_ip and ipaddress.ip_address(attacker_ip).is_global) else 1[m
[32m+[m[32m        except Exception:[m
[32m+[m[32m            is_internal_ip = 0[m
[32m+[m
[32m+[m[32m        fp_result = predict_false_positive([m
[32m+[m[32m            ip_reputation_score=vt_result["risk_score"] if vt_result and not vt_result.get("error") else 0.0,[m
[32m+[m[32m            historical_alert_count=get_historical_alert_count(attacker_ip) if attacker_ip else 0,[m
[32m+[m[32m            is_internal_ip=is_internal_ip,[m
[32m+[m[32m            hour_of_day=hour_of_day,[m
[32m+[m[32m            alert_frequency_spike=1 if hit_count >= max(THRESHOLD * 3, 10) else 0,[m
[32m+[m[32m            geo_risk_score=geo_result["geo_risk_score"] if geo_result else 0.5,[m
[32m+[m[32m            failed_login_ratio=1.0[m
[32m+[m[32m        )[m
[32m+[m[32m        print(f"[ML] FP Probability: {fp_result['fp_probability']}% ({fp_result['label']})")[m
[32m+[m[32m    except FileNotFoundError:[m
[32m+[m[32m        print("[ML] model.pkl not found — skipping FP scoring")[m
[32m+[m[32m    except Exception as e:[m
[32m+[m[32m        print(f"[ML] Could not score false positives: {e}")[m
[32m+[m
     # Store alert in Elasticsearch[m
     alert = {[m
         "@timestamp": datetime.now(timezone.utc).isoformat(),[m
[36m@@ -201,6 +277,10 @@[m [mdef create_alert(hit_count, sample_logs):[m
         "geo_city": geo_result["city"] if geo_result else "unknown",[m
         "geo_country": geo_result["country"] if geo_result else "unknown",[m
         "geo_risk_score": geo_result["geo_risk_score"] if geo_result else 0.5,[m
[32m+[m[32m        "fp_probability": fp_result["fp_probability"] if fp_result else None,[m
[32m+[m[32m        "fp_label": fp_result["label"] if fp_result else None,[m
[32m+[m[32m        "fp_action": fp_result["action"] if fp_result else None,[m
[32m+[m[32m        "fp_reasons": fp_result["reasons"] if fp_result else None,[m
         "status": "open",[m
         "sample_logs": sample_logs[:3][m
     }[m
[36m@@ -214,7 +294,7 @@[m [mdef create_alert(hit_count, sample_logs):[m
         )[m
         if response.status_code == 201:[m
             print(f"[ALERT CREATED] {severity} - {alert['message']}")[m
[31m-            send_slack_alert(hit_count, severity, sample_logs, vt_result, attacker_ip, username, geo_result)[m
[32m+[m[32m            send_slack_alert(hit_count, severity, sample_logs, vt_result, attacker_ip, username, geo_result, fp_result)[m
             return True[m
     except Exception as e:[m
         print(f"[ERROR] Could not create alert: {e}")[m
[1mdiff --git a/requirements.txt b/requirements.txt[m
[1mindex cc9f029..3d4a6d2 100644[m
[1m--- a/requirements.txt[m
[1m+++ b/requirements.txt[m
[36m@@ -4,9 +4,3 @@[m [mgeoip2[m
 pandas[m
 numpy[m
 scikit-learn[m
[31m-requests[m
[31m-python-dotenv[m
[31m-geoip2[m
[31m-pandas[m
[31m-numpy[m
[31m-scikit-learn[m
