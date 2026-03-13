# ============================================================
# SOC Alert Platform — Flask Integration
# ------------------------------------------------------------
# 1. Copy this file to your Flask project root
# 2. Add TWO lines to your app.py:
#    from soc_flask import init_soc_monitor
#    init_soc_monitor(app)
# ============================================================

import threading
import requests
from flask import request, g
import time

SOC_API     = "https://crewless-lastly-homer.ngrok-free.dev/api/ingest"
SOC_API_KEY = "soc-secret-key-2026"
SITE_NAME   = "your-website.com"   # ← change this

SKIP_EXTENSIONS = ('.css', '.js', '.png', '.jpg', '.ico', '.woff')

def _send_log(payload):
    try:
        requests.post(
            SOC_API,
            json=payload,
            headers={"X-API-Key": SOC_API_KEY},
            timeout=2
        )
    except Exception:
        pass

def init_soc_monitor(app):
    @app.after_request
    def log_request(response):
        if any(request.path.endswith(ext) for ext in SKIP_EXTENSIONS):
            return response

        payload = {
            "ip":          request.headers.get("X-Forwarded-For", request.remote_addr),
            "url":         request.full_path,
            "method":      request.method,
            "status_code": response.status_code,
            "site":        SITE_NAME,
            "user_agent":  request.headers.get("User-Agent", ""),
        }

        thread = threading.Thread(target=_send_log, args=(payload,))
        thread.daemon = True
        thread.start()

        return response

    return app
