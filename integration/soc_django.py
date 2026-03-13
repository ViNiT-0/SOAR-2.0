# ============================================================
# SOC Alert Platform — Django Integration
# ------------------------------------------------------------
# 1. Copy this file to your Django project root
# 2. Add to settings.py MIDDLEWARE list:
#    'soc_django.SOCMiddleware',
# ============================================================

import threading
import requests

SOC_API     = "https://crewless-lastly-homer.ngrok-free.dev/api/ingest"
SOC_API_KEY = "soc-secret-key-2026"
SITE_NAME   = "your-website.com"   # ← change this

SKIP_EXTENSIONS = ('.css', '.js', '.png', '.jpg', '.ico', '.woff')

def _send_log(payload):
    """Runs in background thread — never slows down the website."""
    try:
        requests.post(
            SOC_API,
            json=payload,
            headers={"X-API-Key": SOC_API_KEY},
            timeout=2
        )
    except Exception:
        pass  # Silent fail — never breaks your site

class SOCMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Skip static files
        if any(request.path.endswith(ext) for ext in SKIP_EXTENSIONS):
            return response

        payload = {
            "ip":          request.META.get("HTTP_X_FORWARDED_FOR",
                           request.META.get("REMOTE_ADDR", "")),
            "url":         request.get_full_path(),
            "method":      request.method,
            "status_code": response.status_code,
            "site":        SITE_NAME,
            "user_agent":  request.META.get("HTTP_USER_AGENT", ""),
        }

        # Non-blocking — runs in background thread
        thread = threading.Thread(target=_send_log, args=(payload,))
        thread.daemon = True
        thread.start()

        return response
