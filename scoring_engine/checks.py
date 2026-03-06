"""
Service check implementations.
Each check returns (up: bool, message: str).
Checks are designed to validate the service is actually functional,
not just that the port is open.
"""

import socket
import ftplib
import smtplib
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
    HTTP deep check: verify the web server returns HTTP 200 and that
    the response body contains the company portal content
    ('Ludus Corporation' or 'Employee Portal').  A generic 200 from a
    default/placeholder page is not enough.
    """
    url = f"http://{host}:{port}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CCDC-Scoring/1.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(1024)
            if resp.status != 200:
                return False, f"HTTP {resp.status} — unexpected response"
            if not body:
                return False, "HTTP 200 but empty body"
            content = body.decode("utf-8", errors="replace").lower()
            if "ludus corporation" not in content and "employee portal" not in content:
                return False, f"HTTP 200 but company portal content missing ({len(body)} bytes)"
            return True, f"HTTP 200 OK — portal loaded ({len(body)}+ bytes)"
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
        except ftplib.error_perm as e:
            try:
                ftp.quit()
            except Exception:
                pass
            err = str(e)
            # vsftpd sends "500 OOPS: refusing to run with writable root
            # inside chroot()" when anon_root is world-writable and
            # allow_writeable_chroot=YES is absent. That is a misconfigured
            # service, not just anonymous-disabled → score it as DOWN.
            if "500" in err and "OOPS" in err:
                return False, f"vsftpd OOPS — writable chroot not allowed: {err[:80]}"
            # Any other 5xx means anonymous login is disabled but the
            # service itself is running fine (e.g. blue team locked it down).
            return True, f"Service UP (anonymous denied) | {banner[:60]}"
    except ftplib.all_errors as e:
        return False, f"FTP error: {e}"
    except Exception as e:
        return False, str(e)


def check_smtp(host, port):
    """
    SMTP deep check: connect, verify 220 banner, validate EHLO response,
    then send MAIL FROM + RCPT TO + RSET to confirm the MTA relays mail.
    Uses try/finally instead of a context manager to avoid __exit__
    calling quit() on an unconnected socket when connect() fails.
    """
    smtp = smtplib.SMTP(timeout=TIMEOUT)
    try:
        code, banner = smtp.connect(host, port)
        if code != 220:
            return False, f"Expected 220 banner, got {code}"

        code, _ = smtp.ehlo("scoring.ccdc.test")
        if code != 250:
            return False, f"EHLO failed: {code}"

        # Relay test: verify the MTA accepts a mail transaction
        code, _ = smtp.mail("scoring@scoring.ccdc.test")
        if code != 250:
            return False, f"MAIL FROM rejected: {code}"

        code, _ = smtp.rcpt("check@ludus.domain")
        smtp.rset()   # cancel the transaction before disconnecting
        if code not in (250, 251):
            return False, f"RCPT TO rejected: {code}"

        return True, f"SMTP relay OK | {banner.decode(errors='replace')[:55]}"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}"
    except Exception as e:
        return False, str(e)
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


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


def check_ldap(host, port):
    """
    LDAP deep check: send an LDAPv3 anonymous bind request and verify
    the server returns a valid BindResponse (APPLICATION tag 0x61).
    Service is scored UP if LDAP responds at all — even if the server
    denies anonymous access the protocol is confirmed running.
    """
    # Minimal LDAPv3 anonymous bind request (14 bytes)
    bind_request = bytes([
        0x30, 0x0c,        # SEQUENCE (12 bytes total payload)
        0x02, 0x01, 0x01,  # INTEGER messageID = 1
        0x60, 0x07,        # APPLICATION[0] BindRequest (7 bytes)
        0x02, 0x01, 0x03,  # INTEGER version = 3
        0x04, 0x00,        # OCTET STRING dn = "" (anonymous)
        0x80, 0x00,        # [0] IMPLICIT simple password = ""
    ])
    try:
        with _tcp_connect(host, port) as s:
            s.sendall(bind_request)
            data = s.recv(256)
        if len(data) < 7:
            return False, "LDAP: response too short"
        # BindResponse is tagged APPLICATION[1] = 0x61
        if 0x61 not in data:
            return False, "LDAP: no BindResponse tag in reply"
        idx = data.index(0x61)
        inner = data[idx + 2:]   # skip tag + length byte
        if len(inner) >= 3 and inner[0] == 0x0a and inner[1] == 0x01:
            result_code = inner[2]
            if result_code == 0:
                return True, "LDAP anonymous bind OK"
            # Non-zero resultCode still means LDAP is running
            return True, f"LDAP running (anonymous bind resultCode={result_code})"
        return True, "LDAP BindResponse received"
    except socket.timeout:
        return False, "LDAP: connection timed out"
    except ConnectionRefusedError:
        return False, "LDAP: connection refused"
    except Exception as e:
        return False, f"LDAP error: {e}"


def check_smb(host, port):
    """
    SMB deep check: send an SMBv1 NEGOTIATE request and verify the server
    replies with a valid SMB packet.  The response signature reveals
    whether the server answered with SMBv1 (\\xffSMB) or SMBv2+ (\\xfeSMB).
    """
    # SMBv1 NEGOTIATE over NetBIOS-over-TCP (port 445)
    # NetBIOS session header: type=0x00 (SESSION_MESSAGE), 3-byte length = 47
    negotiate = (
        b"\x00\x00\x00\x2f"                      # NetBIOS session header (47 bytes)
        b"\xff\x53\x4d\x42"                       # SMB1 signature
        b"\x72"                                   # SMB_COM_NEGOTIATE
        b"\x00\x00\x00\x00"                       # NT status = 0
        b"\x18"                                   # Flags
        b"\x53\xc8"                               # Flags2
        b"\x00\x00"                               # PID high
        b"\x00\x00\x00\x00\x00\x00\x00\x00"      # Security signature
        b"\x00\x00"                               # Reserved
        b"\xff\xff"                               # TreeID
        b"\x00\x00"                               # PID
        b"\x00\x00"                               # UserID
        b"\x00\x00"                               # MultiplexID
        b"\x00"                                   # Word count = 0
        b"\x0c\x00"                               # Byte count = 12
        b"\x02NT LM 0.12\x00"                    # Dialect string
    )
    try:
        with _tcp_connect(host, port) as s:
            s.sendall(negotiate)
            data = s.recv(512)
        if len(data) < 8:
            return False, "SMB: response too short"
        # SMB signature starts at byte 4 (after the 4-byte NetBIOS header)
        sig = data[4:8]
        if sig == b"\xff\x53\x4d\x42":
            return True, "SMB negotiate OK (SMBv1 response)"
        if sig == b"\xfe\x53\x4d\x42":
            return True, "SMB negotiate OK (SMBv2+ response)"
        return False, f"SMB: unexpected signature: {sig.hex()}"
    except socket.timeout:
        return False, "SMB: connection timed out"
    except ConnectionRefusedError:
        return False, "SMB: connection refused"
    except Exception as e:
        return False, f"SMB error: {e}"


def check_imap_login(host, port, user, password):
    """
    IMAP login check: read server greeting, send tagged LOGIN command,
    and verify a tagged OK response.  Confirms that a real user can
    authenticate — not just that the port is open.
    """
    try:
        with _tcp_connect(host, port) as s:
            greeting = s.recv(512).decode("utf-8", errors="replace").strip()
            if "* OK" not in greeting:
                return False, f"IMAP: unexpected greeting: {greeting[:60]}"
            # Send LOGIN command
            s.sendall(f"A001 LOGIN {user} {password}\r\n".encode())
            resp = s.recv(512).decode("utf-8", errors="replace").strip()
            if "A001 OK" in resp:
                s.sendall(b"A002 LOGOUT\r\n")
                return True, f"IMAP LOGIN OK as '{user}'"
            return False, f"IMAP LOGIN failed: {resp[:60]}"
    except socket.timeout:
        return False, "IMAP: connection timed out"
    except ConnectionRefusedError:
        return False, "IMAP: connection refused"
    except Exception as e:
        return False, f"IMAP error: {e}"


def check_ssh(host, port):
    """
    SSH check: connect and read the server identification string.
    A live SSH daemon always sends a banner starting with 'SSH-'.
    """
    try:
        with _tcp_connect(host, port) as s:
            banner = s.recv(256).decode("utf-8", errors="replace").strip()
            if banner.startswith("SSH-"):
                return True, f"SSH: {banner[:60]}"
            return False, f"SSH: unexpected banner: {banner[:40]}"
    except socket.timeout:
        return False, "SSH: connection timed out"
    except ConnectionRefusedError:
        return False, "SSH: connection refused"
    except Exception as e:
        return False, str(e)


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
    elif ctype == "ldap":
        return check_ldap(host, port)
    elif ctype == "smb":
        return check_smb(host, port)
    elif ctype == "imap_login":
        return check_imap_login(
            host, port,
            service.get("imap_user", "user"),
            service.get("imap_pass", "password"),
        )
    elif ctype == "ssh":
        return check_ssh(host, port)
    else:
        return False, f"Unknown check type: {ctype}"
