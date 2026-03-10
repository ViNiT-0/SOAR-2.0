import re
import ipaddress

def extract_ip_from_logs(log_messages):
    """
    Extracts the first valid external IP from a list of log messages.
    Returns the IP string or None if not found.
    """
    # Quick IPv4 candidate matcher; validity is checked by ipaddress.
    ip_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

    for log in log_messages:
        matches = ip_pattern.findall(log)
        for ip in matches:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue

            # Prefer globally routable IPs (skip private/loopback/link-local/etc).
            if getattr(addr, "is_global", False):
                return str(addr)

    return None


def extract_username_from_logs(log_messages):
    """
    Extracts the targeted username from log messages.
    """
    patterns = [
        r'for user \((\w+)\)',
        r'USER=(\w+)',
        r'for (\w+) from',
        r'user (\w+);'
    ]

    for log in log_messages:
        for pattern in patterns:
            match = re.search(pattern, log)
            if match:
                return match.group(1)

    return "unknown"


if __name__ == "__main__":
    # Test with sample logs
    test_logs = [
        "2026-03-09T15:39:55 localhost sudo: kali : 1 incorrect password attempt ; TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/ls",
        "2026-03-09T15:39:55 localhost sshd: Failed password for root from 185.220.101.45 port 22 ssh2"
    ]

    ip = extract_ip_from_logs(test_logs)
    user = extract_username_from_logs(test_logs)

    print(f"Extracted IP:   {ip}")
    print(f"Extracted User: {user}")
