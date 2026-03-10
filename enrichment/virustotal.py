import requests
import time
import os
from dotenv import load_dotenv

# Load .env from project root
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _base_result(ip, *, verdict, error=None, risk_score=0.0, malicious=0, suspicious=0, total=0,
                 country="Unknown", isp="Unknown"):
    return {
        "ip": ip,
        "verdict": verdict,
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "total_engines": total,
        "risk_score": risk_score,
        "country": country,
        "isp": isp,
        "error": error
    }


def check_ip_reputation(ip, *, timeout=10, max_retries=2):
    """
    Check an IP address against VirusTotal.
    Returns a dictionary with reputation data.
    """

    if not VT_API_KEY:
        return _base_result(ip, verdict="ERROR", error="VT_API_KEY is not set")

    headers = {
        "x-apikey": VT_API_KEY
    }

    retries = 0

    while True:
        try:
            response = requests.get(
                f"{VT_BASE_URL}/ip_addresses/{ip}",
                headers=headers,
                timeout=timeout
            )

            if response.status_code == 200:
                data = response.json()
                attributes = data["data"]["attributes"]

                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)

                total = malicious + suspicious + harmless + undetected

                risk_score = round((malicious + suspicious) / total, 2) if total > 0 else 0.0

                if malicious > 10:
                    verdict = "MALICIOUS"
                elif malicious > 3:
                    verdict = "SUSPICIOUS"
                elif malicious > 0:
                    verdict = "LOW RISK"
                else:
                    verdict = "CLEAN"

                return _base_result(
                    ip,
                    verdict=verdict,
                    malicious=malicious,
                    suspicious=suspicious,
                    total=total,
                    risk_score=risk_score,
                    country=attributes.get("country", "Unknown"),
                    isp=attributes.get("as_owner", "Unknown"),
                    error=None
                )

            elif response.status_code == 404:
                return _base_result(ip, verdict="NOT FOUND", error="IP not found in VirusTotal database")

            elif response.status_code == 429:
                if retries >= max_retries:
                    return _base_result(ip, verdict="ERROR", error="VT rate limit exceeded")

                wait_time = 15 * (retries + 1)
                print(f"[VT] Rate limit hit. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                retries += 1
                continue

            else:
                return _base_result(ip, verdict="ERROR", error=f"HTTP {response.status_code}")

        except Exception as e:
            return _base_result(ip, verdict="ERROR", error=str(e))


def format_vt_summary(vt_result):
    """
    Returns a human readable one-line summary.
    """

    if vt_result.get("error") and vt_result.get("verdict") == "ERROR":
        return f"VT Error: {vt_result['error']}"

    return (
        f"{vt_result['verdict']} — "
        f"{vt_result['malicious_engines']}/{vt_result['total_engines']} engines | "
        f"Risk: {vt_result['risk_score']} | "
        f"Country: {vt_result['country']} | "
        f"ISP: {vt_result['isp']}"
    )


if __name__ == "__main__":

    test_ip = "185.220.101.45"

    print(f"Checking IP: {test_ip}")
    print("-" * 50)

    result = check_ip_reputation(test_ip)

    print(f"Verdict:    {result['verdict']}")
    print(f"Malicious:  {result['malicious_engines']}/{result['total_engines']} engines")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Country:    {result['country']}")
    print(f"ISP:        {result['isp']}")

    print("-" * 50)
    print(f"Summary: {format_vt_summary(result)}")
