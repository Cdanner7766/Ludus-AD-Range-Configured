"""
Service check implementations.
Each check returns (up: bool, message: str).
Checks are designed to validate the service is actually functional,
not just that the port is open.
"""

import socket
import ftplib
import smtplib
import struct
import urllib.request
import urllib.error

try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False

TIMEOUT = 10  # seconds per check


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _tcp_connect(host, port):
    """Open a raw TCP connection and return the socket, or raise."""
    s = socket.create_connection((host, port), timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    return s


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_tcp(host, port):
    """Verify TCP port is open and accepting connections."""
    try:
        with _tcp_connect(host, port):
            return True, "Port open"
    except socket.timeout:
        return False, "Connection timed out"
    except ConnectionRefusedError:
        return False, "Connection refused"
    except OSError as e:
        return False, str(e)


def check_http(host, port):
    """
    HTTP deep check: verify the web server returns HTTP 200.
    Also checks that Apache is serving a non-empty body.
    """
    url = f"http://{host}:{port}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CCDC-Scoring/1.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(512)
            if resp.status == 200 and len(body) > 0:
                return True, f"HTTP 200 OK ({len(body)}+ bytes)"
            return False, f"HTTP {resp.status} — unexpected response"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return False, f"URL error: {e.reason}"
    except Exception as e:
        return False, str(e)


def check_ftp(host, port):
    """
    FTP deep check: connect and attempt anonymous login.
    Service is UP if anonymous auth succeeds or if auth is refused
    but the server is running (auth-required is still a live service).
    """
    try:
        ftp = ftplib.FTP(timeout=TIMEOUT)
        ftp.connect(host, port, timeout=TIMEOUT)
        banner = ftp.getwelcome()
        try:
            ftp.login("anonymous", "scoring@ccdc.test")
            ftp.quit()
            return True, f"Anonymous login OK | {banner[:60]}"
        except ftplib.error_perm:
            ftp.quit()
            return True, f"Service UP (anonymous denied) | {banner[:60]}"
    except ftplib.all_errors as e:
        return False, f"FTP error: {e}"
    except Exception as e:
        return False, str(e)


def check_smtp(host, port):
    """
    SMTP deep check: connect, verify 220 banner, and send EHLO.
    Service is UP if EHLO gets a valid response.
    """
    try:
        with smtplib.SMTP(timeout=TIMEOUT) as smtp:
            code, banner = smtp.connect(host, port)
            if code != 220:
                return False, f"Expected 220, got {code}"
            smtp.ehlo("scoring.ccdc.test")
            return True, f"EHLO accepted | {banner.decode(errors='replace')[:60]}"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}"
    except Exception as e:
        return False, str(e)


def check_banner(host, port, expected=None):
    """
    Banner check: connect to a TCP service and read the greeting.
    Optionally verify the banner contains an expected substring.
    Used for IMAP (expects '* OK') and POP3 (expects '+OK').
    """
    try:
        with _tcp_connect(host, port) as s:
            raw = s.recv(1024)
            banner = raw.decode("utf-8", errors="replace").strip()
            if expected and expected not in banner:
                return False, f"Banner missing '{expected}': {banner[:80]}"
            return True, f"Banner: {banner[:80]}"
    except socket.timeout:
        return False, "Connection timed out"
    except ConnectionRefusedError:
        return False, "Connection refused"
    except Exception as e:
        return False, str(e)


def check_mysql(host, port):
    """
    MySQL deep check: parse the server handshake packet to confirm
    MySQL/MariaDB is running and extract the server version.
    MySQL sends a greeting (protocol byte 0x0a) immediately on connect.
    """
    try:
        with _tcp_connect(host, port) as s:
            data = s.recv(256)
            if len(data) < 5:
                return False, "Incomplete handshake"
            # MySQL packet: 3-byte length + 1-byte seq + payload
            # Payload byte 0 is the protocol version (10 = modern MySQL)
            proto = data[4]
            if proto == 0x0a:
                # Version string ends at first null byte after byte 5
                try:
                    null_idx = data.index(b"\x00", 5)
                    version = data[5:null_idx].decode("ascii", errors="replace")
                    return True, f"MySQL/MariaDB {version}"
                except ValueError:
                    return True, "MySQL handshake OK (version unreadable)"
            elif proto == 0xff:
                # Error packet
                err_msg = data[7:].decode("utf-8", errors="replace")[:60]
                return False, f"MySQL error: {err_msg}"
            else:
                return True, f"DB port open (proto byte=0x{proto:02x})"
    except socket.timeout:
        return False, "Connection timed out"
    except ConnectionRefusedError:
        return False, "Connection refused"
    except Exception as e:
        return False, str(e)


def check_dns(host, query, expected_ip=None):
    """
    DNS deep check: query the target DNS server to resolve a hostname.
    Verifies the DNS server is responding to queries.
    Uses dnspython if available, otherwise falls back to a raw UDP query.
    """
    if _HAS_DNSPYTHON:
        return _dns_dnspython(host, query, expected_ip)
    return _dns_raw_udp(host, query, expected_ip)


def _dns_dnspython(host, query, expected_ip):
    import dns.resolver
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [host]
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        answers = resolver.resolve(query, "A")
        ips = [str(r) for r in answers]
        if expected_ip and expected_ip not in ips:
            return False, f"Expected {expected_ip}, got {ips}"
        return True, f"Resolved {query} → {', '.join(ips)}"
    except Exception as e:
        return False, f"DNS query failed: {e}"


def _dns_raw_udp(host, query, expected_ip):
    """
    Minimal raw UDP DNS query for environments without dnspython.
    Builds a DNS A-record query packet by hand and checks for a valid response.
    """
    try:
        # Build a minimal DNS query for an A record
        txn_id = b"\xab\xcd"
        flags = b"\x01\x00"          # standard query, recursion desired
        qdcount = b"\x00\x01"
        ancount = b"\x00\x00"
        nscount = b"\x00\x00"
        arcount = b"\x00\x00"
        header = txn_id + flags + qdcount + ancount + nscount + arcount

        # Encode QNAME
        qname = b""
        for label in query.split("."):
            encoded = label.encode()
            qname += bytes([len(encoded)]) + encoded
        qname += b"\x00"

        qtype = b"\x00\x01"   # A record
        qclass = b"\x00\x01"  # IN class
        packet = header + qname + qtype + qclass

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            s.sendto(packet, (host, 53))
            response, _ = s.recvfrom(512)

        if len(response) < 12:
            return False, "Short DNS response"
        rcode = response[3] & 0x0F
        if rcode == 0:
            return True, f"DNS query OK (NOERROR) for {query}"
        return False, f"DNS RCODE {rcode} for {query}"
    except socket.timeout:
        return False, "DNS query timed out"
    except Exception as e:
        return False, f"DNS raw query error: {e}"


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def run_check(service):
    """
    Run the appropriate check for a service definition.
    Returns (up: bool, message: str).
    """
    ctype = service["check_type"]
    host = service["host"]
    port = service["port"]

    if ctype == "tcp":
        return check_tcp(host, port)
    elif ctype == "http":
        return check_http(host, port)
    elif ctype == "ftp":
        return check_ftp(host, port)
    elif ctype == "smtp":
        return check_smtp(host, port)
    elif ctype == "banner":
        return check_banner(host, port, service.get("banner_expect"))
    elif ctype == "mysql":
        return check_mysql(host, port)
    elif ctype == "dns":
        return check_dns(
            host,
            service.get("dns_query", "ludus.domain"),
            service.get("dns_expected_ip"),
        )
    else:
        return False, f"Unknown check type: {ctype}"
