import requests
import time

VT_API_KEY = "68a3e25e953413fe479452ce75834e709b2fb502126afb9115fc5e0063063656"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

def check_ip_reputation(ip):
    """
    Check an IP address against VirusTotal.
    Returns a dict with reputation data.
    """
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(
            f"{VT_BASE_URL}/ip_addresses/{ip}",
            headers=headers
        )

        if response.status_code == 200:
            data = response.json()
            attributes = data["data"]["attributes"]

            # Extract key stats
            stats = attributes.get("last_analysis_stats", {})
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            harmless    = stats.get("harmless", 0)
            undetected  = stats.get("undetected", 0)
            total       = malicious + suspicious + harmless + undetected

            # Calculate risk score (0.0 to 1.0)
            risk_score = round((malicious + suspicious) / total, 2) if total > 0 else 0.0

            # Determine verdict
            if malicious > 10:
                verdict = "MALICIOUS"
            elif malicious > 3:
                verdict = "SUSPICIOUS"
            elif malicious > 0:
                verdict = "LOW RISK"
            else:
                verdict = "CLEAN"

            return {
                "ip": ip,
                "verdict": verdict,
                "malicious_engines": malicious,
                "suspicious_engines": suspicious,
                "total_engines": total,
                "risk_score": risk_score,
                "country": attributes.get("country", "Unknown"),
                "isp": attributes.get("as_owner", "Unknown"),
                "error": None
            }

        elif response.status_code == 404:
            return {
                "ip": ip,
                "verdict": "NOT FOUND",
                "malicious_engines": 0,
                "suspicious_engines": 0,
                "total_engines": 0,
                "risk_score": 0.0,
                "country": "Unknown",
                "isp": "Unknown",
                "error": "IP not found in VirusTotal database"
            }

        elif response.status_code == 429:
            print("[VT] Rate limit hit — waiting 60 seconds...")
            time.sleep(60)
            return check_ip_reputation(ip)

        else:
            return {
                "ip": ip,
                "verdict": "ERROR",
                "risk_score": 0.0,
                "error": f"HTTP {response.status_code}"
            }

    except Exception as e:
        return {
            "ip": ip,
            "verdict": "ERROR",
            "risk_score": 0.0,
            "error": str(e)
        }


def format_vt_summary(vt_result):
    """
    Returns a human readable one-line summary.
    """
    if vt_result["error"] and vt_result["verdict"] == "ERROR":
        return f"VT Error: {vt_result['error']}"

    return (
        f"{vt_result['verdict']} — "
        f"{vt_result['malicious_engines']}/{vt_result['total_engines']} engines | "
        f"Risk: {vt_result['risk_score']} | "
        f"Country: {vt_result['country']} | "
        f"ISP: {vt_result['isp']}"
    )


if __name__ == "__main__":
    # Quick test
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
