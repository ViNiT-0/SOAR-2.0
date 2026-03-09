import re

def extract_ip_from_logs(log_messages):
    """
    Extracts the first valid external IP from a list of log messages.
    Returns the IP string or None if not found.
    """
    # Pattern matches standard IPv4
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    # These are internal/private IP ranges — skip them
    def is_internal(ip):
        return (
            ip.startswith("127.") or
            ip.startswith("192.168.") or
            ip.startswith("10.") or
            ip.startswith("172.16.") or
            ip.startswith("172.17.") or
            ip.startswith("0.") or
            ip == "255.255.255.255"
        )

    for log in log_messages:
        matches = ip_pattern.findall(log)
        for ip in matches:
            if not is_internal(ip):
                return ip

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
