"""
Scoring engine configuration.
Range ID and target IPs are auto-detected from the Kali machine's IP address.
Kali lives on 10.{RANGE_ID}.99.x and services are on 10.{RANGE_ID}.10.x
"""

import subprocess


def _detect_range_id():
    """Detect the Ludus range ID from Kali's IP (10.X.99.Y pattern)."""
    try:
        result = subprocess.run(
            ["ip", "addr", "show"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "inet " not in line or "127.0.0.1" in line:
                continue
            ip = line.strip().split()[1].split("/")[0]
            parts = ip.split(".")
            if len(parts) == 4 and parts[0] == "10" and parts[2] == "99":
                return int(parts[1])
    except Exception:
        pass
    return 10  # Default fallback


RANGE_ID = _detect_range_id()
BASE_NET = f"10.{RANGE_ID}.10"

# How often to run a full check round (seconds)
CHECK_INTERVAL = 60

# ------------------------------------------------------------------
# Service definitions
# Each service specifies:
#   id           - unique key used in the database
#   name         - human-readable label
#   machine      - VM name from range-config.yaml
#   host         - target IP
#   port         - TCP port
#   points       - points awarded per round when service is UP
#   check_type   - one of: http, ftp, smtp, banner, dns, mysql, tcp
# ------------------------------------------------------------------
def _build_services():
    n = BASE_NET
    return [
        {
            "id": "http",
            "name": "HTTP Web Server",
            "machine": "WEB01",
            "host": f"{n}.31",
            "port": 80,
            "points": 100,
            "check_type": "http",
        },
        {
            "id": "ftp",
            "name": "FTP Server",
            "machine": "FTP01",
            "host": f"{n}.81",
            "port": 21,
            "points": 50,
            "check_type": "ftp",
        },
        {
            "id": "smtp",
            "name": "SMTP (Mail)",
            "machine": "MAIL01",
            "host": f"{n}.61",
            "port": 25,
            "points": 75,
            "check_type": "smtp",
        },
        {
            "id": "imap",
            "name": "IMAP (Mail)",
            "machine": "MAIL01",
            "host": f"{n}.61",
            "port": 143,
            "points": 50,
            "check_type": "banner",
            "banner_expect": "* OK",
        },
        {
            "id": "pop3",
            "name": "POP3 (Mail)",
            "machine": "MAIL01",
            "host": f"{n}.61",
            "port": 110,
            "points": 50,
            "check_type": "banner",
            "banner_expect": "+OK",
        },
        {
            "id": "dns",
            "name": "DNS Server",
            "machine": "DNS01",
            "host": f"{n}.71",
            "port": 53,
            "points": 100,
            "check_type": "dns",
            "dns_query": "web.ludus.domain",
            "dns_expected_ip": f"{n}.31",
        },
        {
            "id": "mysql",
            "name": "MySQL Database",
            "machine": "DB01",
            "host": f"{n}.41",
            "port": 3306,
            "points": 75,
            "check_type": "mysql",
        },
        {
            "id": "smb",
            "name": "SMB File Share",
            "machine": "FILESVR",
            "host": f"{n}.51",
            "port": 445,
            "points": 50,
            "check_type": "tcp",
        },
        {
            "id": "ldap",
            "name": "LDAP (Active Directory)",
            "machine": "DC01",
            "host": f"{n}.11",
            "port": 389,
            "points": 100,
            "check_type": "tcp",
        },
        {
            "id": "kerberos",
            "name": "Kerberos (Active Directory)",
            "machine": "DC01",
            "host": f"{n}.11",
            "port": 88,
            "points": 100,
            "check_type": "tcp",
        },
    ]


SERVICES = _build_services()
MAX_SCORE_PER_ROUND = sum(s["points"] for s in SERVICES)
