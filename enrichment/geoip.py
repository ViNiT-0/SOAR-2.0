import geoip2.database
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                        "data", "GeoLite2-City.mmdb")

# Country code to flag emoji mapping
COUNTRY_FLAGS = {
    "US": "🇺🇸", "RU": "🇷🇺", "CN": "🇨🇳", "DE": "🇩🇪",
    "GB": "🇬🇧", "FR": "🇫🇷", "IN": "🇮🇳", "BR": "🇧🇷",
    "NL": "🇳🇱", "UA": "🇺🇦", "KP": "🇰🇵", "IR": "🇮🇷",
    "PK": "🇵🇰", "TR": "🇹🇷", "KR": "🇰🇷", "JP": "🇯🇵",
    "CA": "🇨🇦", "AU": "🇦🇺", "SG": "🇸🇬", "HK": "🇭🇰"
}

# Countries considered high risk for SOC purposes
HIGH_RISK_COUNTRIES = [
    "RU", "CN", "KP", "IR", "SY", "CU", "VE"
]

def get_location(ip):
    """
    Returns location info for a given IP address.
    """
    try:
        with geoip2.database.Reader(DB_PATH) as reader:
            response = reader.city(ip)

            country_code = response.country.iso_code or "Unknown"
            country_name = response.country.name or "Unknown"
            city = response.city.name or "Unknown"
            latitude = response.location.latitude
            longitude = response.location.longitude
            flag = COUNTRY_FLAGS.get(country_code, "🌐")
            is_high_risk = country_code in HIGH_RISK_COUNTRIES

            return {
                "ip": ip,
                "city": city,
                "country": country_name,
                "country_code": country_code,
                "flag": flag,
                "latitude": latitude,
                "longitude": longitude,
                "is_high_risk": is_high_risk,
                "geo_risk_score": 0.9 if is_high_risk else 0.3,
                "error": None
            }

    except geoip2.errors.AddressNotFoundError:
        return {
            "ip": ip,
            "city": "Unknown",
            "country": "Unknown",
            "country_code": "Unknown",
            "flag": "🌐",
            "latitude": None,
            "longitude": None,
            "is_high_risk": False,
            "geo_risk_score": 0.5,
            "error": "IP not found in GeoIP database"
        }
    except Exception as e:
        return {
            "ip": ip,
            "city": "Unknown",
            "country": "Unknown",
            "country_code": "Unknown",
            "flag": "🌐",
            "is_high_risk": False,
            "geo_risk_score": 0.5,
            "error": str(e)
        }

def format_location(geo_result):
    """
    Returns a human readable location string.
    """
    if geo_result["error"] and geo_result["city"] == "Unknown":
        return f"Location unknown ({geo_result['error']})"

    risk_tag = " ⚠️ HIGH RISK COUNTRY" if geo_result["is_high_risk"] else ""
    return (
        f"{geo_result['flag']} {geo_result['city']}, "
        f"{geo_result['country']}{risk_tag}"
    )


if __name__ == "__main__":
    test_ips = [
        "185.220.101.45",   # Known Tor exit node (Germany)
        "8.8.8.8",          # Google DNS (US)
        "1.1.1.1",          # Cloudflare (AU)
    ]

    for ip in test_ips:
        result = get_location(ip)
        print(f"IP:       {ip}")
        print(f"Location: {format_location(result)}")
        print(f"Risk:     {result['geo_risk_score']}")
        print("-" * 40)
