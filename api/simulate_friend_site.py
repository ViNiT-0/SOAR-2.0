import requests
import random
import time
from datetime import datetime

API_URL = "http://localhost:8000/api/ingest"
API_KEY = "soc-secret-key-2026"

SITE = "friends-portfolio.com"

# Realistic attacker IPs
ATTACKER_IPS = [
    "185.220.101.45",  # Known Tor exit node
    "45.33.32.156",    # Shodan scanner
    "103.21.244.11",   # Asia Pacific
    "91.108.4.0",      # Eastern Europe
    "194.165.16.11",   # Russia
]

# Normal visitor IPs
NORMAL_IPS = [
    "49.36.100.12",
    "122.161.50.20",
    "106.193.100.45",
    "157.35.224.10",
    "72.229.28.185",
]

NORMAL_PAGES = [
    "/", "/about", "/contact", "/projects",
    "/blog", "/resume", "/portfolio", "/index.html"
]

ATTACK_SCENARIOS = [
    # (url, method, status, label)
    ("/login?id=1 UNION SELECT username,password FROM users", "GET",  200, "SQL Injection"),
    ("/search?q=<script>alert(document.cookie)</script>",    "GET",  200, "XSS"),
    ("/download?file=../../../etc/passwd",                   "GET",  200, "Path Traversal"),
    ("/wp-admin",                                            "GET",  404, "Admin Probe"),
    ("/.env",                                                "GET",  404, "Env File Probe"),
    ("/.git/config",                                         "GET",  404, "Git Probe"),
    ("/phpmyadmin",                                          "GET",  404, "phpMyAdmin Probe"),
    ("/login",                                               "POST", 401, "Brute Force attempt"),
    ("/api/users?filter=1' OR '1'='1",                       "GET",  200, "SQL Injection API"),
    ("/upload?file=shell.php%00.jpg",                        "POST", 200, "File Upload Attack"),
]

def send(ip, url, method, status_code, label=""):
    payload = {
        "ip":          ip,
        "url":         url,
        "method":      method,
        "status_code": status_code,
        "site":        SITE,
    }
    try:
        r = requests.post(
            API_URL,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key":    API_KEY
            },
            timeout=5
        )
        result = r.json()
        triggered = result.get("triggered", False)
        tag = "🚨 ALERT" if triggered else "📋 logged"
        print(f"  {tag}  {method:4}  {str(status_code)}  {url[:55]:55}  ({label})")
    except Exception as e:
        print(f"  ❌ ERROR: {e}")

def simulate_normal_traffic(count=5):
    print(f"\n[Normal Traffic — {count} requests]")
    for _ in range(count):
        ip     = random.choice(NORMAL_IPS)
        page   = random.choice(NORMAL_PAGES)
        status = random.choice([200, 200, 200, 304])
        send(ip, page, "GET", status, "normal visit")
        time.sleep(0.3)

def simulate_attack(scenario):
    url, method, status, label = scenario
    ip = random.choice(ATTACKER_IPS)
    print(f"\n[Attack: {label}]")
    send(ip, url, method, status, label)

def simulate_brute_force(count=12):
    ip = random.choice(ATTACKER_IPS)
    print(f"\n[Brute Force — {count} login attempts from {ip}]")
    for i in range(1, count + 1):
        print(f"  attempt {i:02}/{count}", end="  ")
        send(ip, "/login", "POST", 401, f"attempt {i}")
        time.sleep(1.2)

def run():
    print("=" * 65)
    print(f"  SOC Platform — Friend Site Simulator")
    print(f"  Site: {SITE}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    # Round 1 — normal traffic
    simulate_normal_traffic(6)
    time.sleep(1)

    # Round 2 — SQL injection
    simulate_attack(ATTACK_SCENARIOS[0])
    time.sleep(2)

    # Round 3 — more normal traffic
    simulate_normal_traffic(4)
    time.sleep(1)

    # Round 4 — XSS
    simulate_attack(ATTACK_SCENARIOS[1])
    time.sleep(2)

    # Round 5 — path traversal
    simulate_attack(ATTACK_SCENARIOS[2])
    time.sleep(2)

    # Round 6 — admin probing (3 different probe paths)
    print("\n[Admin Probing — 3 paths]")
    ip = random.choice(ATTACKER_IPS)
    for scenario in ATTACK_SCENARIOS[3:7]:
        url, method, status, label = scenario
        send(ip, url, method, status, label)
        time.sleep(1)

    # Round 7 — normal traffic again
    simulate_normal_traffic(5)
    time.sleep(1)

    # Round 8 — brute force (this WILL trigger the alert)
    simulate_brute_force(12)
    time.sleep(2)

    # Round 9 — API attack
    simulate_attack(ATTACK_SCENARIOS[8])
    time.sleep(1)

    print("\n" + "=" * 65)
    print("  Simulation complete!")
    print(f"  Check Slack #soc-alerts for alerts")
    print(f"  Check Kibana → web-logs index for all traffic")
    print("=" * 65)

if __name__ == "__main__":
    run()
