"""
Service check implementations.
Each check returns (up: bool, message: str).
Checks are designed to validate the service is actually functional,
not just that the port is open.
"""

import hashlib
import hmac as _hmac_mod
import os
import socket
import ssl
import struct
import time
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

        # Use a real local account on MAIL01 so Postfix accepts local delivery.
        # "check@ludus.domain" would be rejected (550 User unknown) because
        # ludus.domain is in mydestination and "check" is not a real user.
        code, _ = smtp.rcpt("user@ludus.domain")
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

    Windows Server 2022 establishes the TCP connection successfully but then
    sends a TCP RST after receiving an SMBv1-only NEGOTIATE when SMBv1 is
    disabled or not yet active (e.g. pending reboot after feature install).
    A post-connect RST means port 445 IS open and the SMB service IS running
    — the host just refused the specific dialect.  We treat this as UP because
    the service is reachable; a blue team can still access shares via SMBv2.
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
    # Open the connection first — if this fails the service is genuinely down.
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
    except socket.timeout:
        return False, "SMB: connection timed out"
    except ConnectionRefusedError:
        return False, "SMB: connection refused"
    except OSError as e:
        return False, f"SMB: {e}"

    # Connection established — send the negotiate and read the response.
    try:
        sock.sendall(negotiate)
        data = sock.recv(512)
    except (ConnectionResetError, ConnectionAbortedError):
        # Port 445 accepted the TCP connection but Windows RST'd it after
        # receiving the SMBv1 negotiate (SMBv1 disabled / pending reboot).
        # The SMB service IS running — score it as UP.
        return True, "SMB: service UP (SMBv1 rejected, SMBv2-only host)"
    except socket.timeout:
        return False, "SMB: timed out waiting for negotiate response"
    except Exception as e:
        return False, f"SMB error: {e}"
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if len(data) < 4:
        return False, "SMB: response too short"
    # NetBIOS negative session response (0x83) = hard rejection
    if data[0] == 0x83:
        return False, "SMB: NetBIOS session rejected"
    if len(data) >= 8:
        sig = data[4:8]
        if sig == b"\xff\x53\x4d\x42":
            return True, "SMB negotiate OK (SMBv1 response)"
        if sig == b"\xfe\x53\x4d\x42":
            return True, "SMB negotiate OK (SMBv2+ response)"
    # Any other SESSION_MESSAGE (first byte 0x00) means SMB responded
    if data[0] == 0x00:
        return True, f"SMB: service responding ({len(data)} bytes)"
    return False, f"SMB: unexpected response: {data[:8].hex()}"


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
# RDP NLA (CredSSP v5 / NTLMv2) authentication check
# ---------------------------------------------------------------------------
# Implements the full RDP Network Level Authentication handshake:
#   TCP → X.224 (COTP) → TLS → CredSSP v5 (NTLM NEGOTIATE → CHALLENGE →
#   AUTHENTICATE + pubKeyAuth) so that we can confirm a domain account can
#   actually log into the workstation, not just that port 3389 is open.
#
# CredSSP protocol version 5 (required by default on Windows 10 1703+ /
# Server 2016+ after the CVE-2018-0886 patch) uses a SHA-256 hash of the
# server's TLS certificate for pubKeyAuth rather than the raw public key.

def _md4(data: bytes) -> bytes:
    """
    Pure-Python MD4 (RFC 1320). Used to compute the NT hash from the password.
    Needed because OpenSSL 3.x (Python 3.12+ on Kali) removed the legacy MD4
    digest, so hashlib.new('md4', ...) may raise ValueError.
    """
    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z
    def _rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    M = 0xFFFFFFFF
    msg = bytearray(data)
    bit_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        X = list(struct.unpack_from("<16I", msg, off))
        a, b, c, d = A, B, C, D

        # Round 1 — F, no addend, indices 0-15, shifts 3/7/11/19
        for i in range(16):
            t = (_rol((a + _f(b, c, d) + X[i]) & M, [3, 7, 11, 19][i % 4]))
            a, b, c, d = d, t, b, c

        # Round 2 — G, addend 0x5A827999, index order 0,4,8,12,…
        R2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i in range(16):
            t = (_rol((a + _g(b, c, d) + X[R2[i]] + 0x5A827999) & M,
                      [3, 5, 9, 13][i % 4]))
            a, b, c, d = d, t, b, c

        # Round 3 — H, addend 0x6ED9EBA1, index order 0,8,4,12,…
        R3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            t = (_rol((a + _h(b, c, d) + X[R3[i]] + 0x6ED9EBA1) & M,
                      [3, 9, 11, 15][i % 4]))
            a, b, c, d = d, t, b, c

        A = (A + a) & M; B = (B + b) & M
        C = (C + c) & M; D = (D + d) & M

    return struct.pack("<4I", A, B, C, D)


def _nt_hash(password: str) -> bytes:
    """NT hash = MD4(UTF-16LE encoded password)."""
    pw = password.encode("utf-16-le")
    try:
        return hashlib.new("md4", pw).digest()
    except ValueError:
        return _md4(pw)


def _rc4(key: bytes, data: bytes) -> bytes:
    """RC4 stream cipher (used for NTLMv2 key exchange)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) % 256])
    return bytes(out)


def _hmac_md5(key: bytes, msg: bytes) -> bytes:
    return _hmac_mod.new(key, msg, hashlib.md5).digest()


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return _hmac_mod.new(key, msg, hashlib.sha256).digest()


def _ntlm_negotiate() -> bytes:
    """Build NTLM Type-1 NEGOTIATE_MESSAGE."""
    flags = (
        0x00000001 |  # UNICODE
        0x00000200 |  # NTLM
        0x00008000 |  # REQUEST_TARGET
        0x00020000 |  # ALWAYS_SIGN
        0x00080000 |  # EXTENDED_SESSIONSECURITY
        0x20000000 |  # 128-bit
        0x40000000 |  # KEY_EXCH
        0x80000000    # 56-bit
    )
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 1)     # MessageType = 1
        + struct.pack("<I", flags)
        + b"\x00" * 8              # DomainNameFields (empty)
        + b"\x00" * 8              # WorkstationFields (empty)
        + b"\x06\x01\x00\x00\x00\x00\x00\x0f"  # Version 6.1 / NTLMRevision 15
    )


def _ntlm_authenticate(domain: str, user: str, password: str,
                        server_challenge: bytes,
                        target_info: bytes) -> tuple[bytes, bytes]:
    """
    Build NTLM Type-3 AUTHENTICATE_MESSAGE with NTLMv2 response.
    Returns (authenticate_bytes, exported_session_key).
    """
    nt_h = _nt_hash(password)
    response_key = _hmac_md5(nt_h, (user.upper() + domain).encode("utf-16-le"))

    client_challenge = os.urandom(8)
    ts = struct.pack("<Q", int((time.time() + 11644473600) * 10_000_000))

    blob = (
        b"\x01\x01\x00\x00"   # Blob signature
        b"\x00\x00\x00\x00"   # Reserved
        + ts
        + client_challenge
        + b"\x00\x00\x00\x00" # Reserved
        + target_info
        + b"\x00\x00\x00\x00" # EOL MsvAvEOL padding
    )
    nt_proof = _hmac_md5(response_key, server_challenge + blob)
    nt_response = nt_proof + blob

    session_base_key = _hmac_md5(response_key, nt_proof)
    exported_session_key = os.urandom(16)
    encrypted_session_key = _rc4(session_base_key, exported_session_key)

    flags = (
        0x00000001 | 0x00000200 | 0x00008000 |
        0x00020000 | 0x00080000 | 0x20000000 |
        0x40000000 | 0x80000000
    )

    domain_b = domain.encode("utf-16-le")
    user_b   = user.encode("utf-16-le")
    ws_b     = b"KALI\x00\x00\x00\x00"  # workstation (UTF-16LE)
    lm_resp  = b"\x00" * 24

    # Fixed header: 8 sig + 4 type + 8*6 fields + 4 flags + 8 ver + 16 MIC = 88
    off = 88
    def fld(data):
        nonlocal off
        f = struct.pack("<HHI", len(data), len(data), off)
        off += len(data)
        return f

    lm_f  = fld(lm_resp)
    nt_f  = fld(nt_response)
    dom_f = fld(domain_b)
    usr_f = fld(user_b)
    ws_f  = fld(ws_b)
    esk_f = fld(encrypted_session_key)

    msg = (
        b"NTLMSSP\x00"
        + struct.pack("<I", 3)
        + lm_f + nt_f + dom_f + usr_f + ws_f + esk_f
        + struct.pack("<I", flags)
        + b"\x06\x01\x00\x00\x00\x00\x00\x0f"  # Version
        + b"\x00" * 16                            # MIC (zeroed)
        + lm_resp + nt_response
        + domain_b + user_b + ws_b
        + encrypted_session_key
    )
    return msg, exported_session_key


def _credssp_pub_key_auth(session_key: bytes, cert_der: bytes,
                           client_nonce: bytes) -> bytes:
    """
    CredSSP v5 pubKeyAuth (MS-CSSP §3.1.5.2):
      binding_key  = HMAC-SHA256(ExportedSessionKey, "CredSSP Client-To-Server Binding Hash\0")
      pubKeyAuth   = HMAC-SHA256(binding_key, SHA256(serverCert) + clientNonce)
    """
    binding_key = _hmac_sha256(
        session_key,
        b"CredSSP Client-To-Server Binding Hash\x00"
    )
    cert_hash = hashlib.sha256(cert_der).digest()
    return _hmac_sha256(binding_key, cert_hash + client_nonce)


# ── DER / ASN.1 helpers for CredSSP TSRequest encoding ──────────────────────

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def _tlv(tag: int, data: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(data)) + data


def _ts_request_round1(ntlm_neg: bytes, client_nonce: bytes) -> bytes:
    """TSRequest v6: version + negoTokens + clientNonce."""
    ver   = _tlv(0xA0, _tlv(0x02, b"\x06"))
    nego  = _tlv(0xA1, _tlv(0x30, _tlv(0x30, _tlv(0xA0, _tlv(0x04, ntlm_neg)))))
    nonce = _tlv(0xA5, _tlv(0x04, client_nonce))
    return _tlv(0x30, ver + nego + nonce)


def _ts_request_round3(ntlm_auth: bytes, pub_key_auth: bytes) -> bytes:
    """TSRequest v6: version + negoTokens + pubKeyAuth."""
    ver  = _tlv(0xA0, _tlv(0x02, b"\x06"))
    nego = _tlv(0xA1, _tlv(0x30, _tlv(0x30, _tlv(0xA0, _tlv(0x04, ntlm_auth)))))
    pka  = _tlv(0xA3, _tlv(0x04, pub_key_auth))
    return _tlv(0x30, ver + nego + pka)


def _read_der(sock) -> bytes:
    """Read one complete DER SEQUENCE from a TLS socket."""
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return hdr
        hdr += chunk
    if hdr[0] != 0x30:
        return hdr + sock.recv(4096)
    b1 = hdr[1]
    if b1 < 0x80:
        total = 2 + b1
    elif b1 == 0x81:
        total = 3 + hdr[2]
    elif b1 == 0x82:
        total = 4 + (hdr[2] << 8 | hdr[3])
    else:
        return hdr + sock.recv(4096)
    data = hdr
    while len(data) < total:
        chunk = sock.recv(min(total - len(data), 8192))
        if not chunk:
            break
        data += chunk
    return data


def _extract_ntlm(ts_req: bytes) -> bytes:
    """Pull the raw NTLM message out of a CredSSP TSRequest."""
    idx = ts_req.find(b"NTLMSSP\x00")
    if idx < 0:
        return b""
    # Walk back to find the OCTET STRING (0x04) tag that wraps the token
    for i in range(max(0, idx - 4), idx):
        if ts_req[i] != 0x04:
            continue
        pos = i + 1
        b0 = ts_req[pos]
        if b0 < 0x80:
            return ts_req[i + 2: i + 2 + b0]
        if b0 == 0x81:
            n = ts_req[pos + 1]
            return ts_req[i + 3: i + 3 + n]
        if b0 == 0x82:
            n = (ts_req[pos + 1] << 8) | ts_req[pos + 2]
            return ts_req[i + 4: i + 4 + n]
    return ts_req[idx:]


def check_rdp_login(host: str, port: int,
                    domain: str, user: str, password: str) -> tuple[bool, str]:
    """
    RDP NLA (CredSSP v5 / NTLMv2) authentication check.

    Flow:
      1. TCP connect to 3389
      2. X.224 COTP Connection Request asking for NLA (PROTOCOL_HYBRID)
      3. X.224 Connection Confirm — verify server accepted NLA
      4. TLS upgrade
      5. CredSSP round 1: send TSRequest{version=6, NTLM_NEGOTIATE, clientNonce}
      6. CredSSP round 2: parse TSRequest{NTLM_CHALLENGE} from server
      7. CredSSP round 3: send TSRequest{NTLM_AUTHENTICATE, pubKeyAuth}
      8. CredSSP round 4: server sends pubKeyAuth back on success,
                          or errorCode / connection close on failure
    """
    # X.224 Connection Request — requestedProtocols = SSL(1) | HYBRID/NLA(2) = 3
    x224_req = (
        b"\x03\x00\x00\x13"   # TPKT: version=3, length=19
        b"\x0e"                # COTP length indicator (14 bytes follow)
        b"\xe0"                # CR TPDU
        b"\x00\x00"            # DST-REF
        b"\x00\x00"            # SRC-REF
        b"\x00"                # Class options
        b"\x01\x00\x08\x00"   # RDP_NEG_REQ, flags=0, length=8
        b"\x03\x00\x00\x00"   # requestedProtocols = HYBRID | SSL
    )

    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        sock.sendall(x224_req)

        resp = sock.recv(1024)
        if not resp or resp[0] != 0x03:
            sock.close()
            return False, "RDP: no valid X.224 response"

        # Expect CC TPDU (0xD0); check RDP_NEG_RSP selected protocol
        if len(resp) >= 19 and resp[5] == 0xD0 and resp[11] == 0x02:
            sel = struct.unpack_from("<I", resp, 15)[0]
            if sel not in (0x02, 0x03):
                sock.close()
                return False, f"RDP: NLA not available (server selected 0x{sel:x})"

        # TLS upgrade
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(sock, server_hostname=host)

        server_cert_der = tls.getpeercert(binary_form=True)
        client_nonce = os.urandom(32)

        # Round 1: NTLM NEGOTIATE
        tls.sendall(_ts_request_round1(_ntlm_negotiate(), client_nonce))

        # Round 2: NTLM CHALLENGE
        ts2 = _read_der(tls)
        challenge_msg = _extract_ntlm(ts2)
        if len(challenge_msg) < 32 or challenge_msg[8:12] != b"\x02\x00\x00\x00":
            tls.close()
            return False, "RDP: expected NTLM CHALLENGE, got unexpected response"

        server_challenge = challenge_msg[24:32]
        ti_len, _, ti_off = struct.unpack_from("<HHI", challenge_msg, 40)
        target_info = challenge_msg[ti_off: ti_off + ti_len]

        # Round 3: NTLM AUTHENTICATE + pubKeyAuth
        auth_msg, session_key = _ntlm_authenticate(
            domain, user, password, server_challenge, target_info
        )
        pub_key_auth = _credssp_pub_key_auth(
            session_key, server_cert_der, client_nonce
        )
        tls.sendall(_ts_request_round3(auth_msg, pub_key_auth))

        # Round 4: server response
        try:
            tls.settimeout(6)
            ts4 = _read_der(tls)
        except (ssl.SSLError, OSError):
            # Server closed connection — treat as auth failure
            tls.close()
            return False, f"RDP: auth rejected for '{domain}\\{user}'"
        except socket.timeout:
            tls.close()
            return False, "RDP: timed out waiting for auth response"

        tls.close()

        # errorCode is context tag [4] = 0xA4 in the TSRequest
        if b"\xa4" in ts4:
            ei = ts4.index(b"\xa4")
            inner = ts4[ei + 2:]
            if len(inner) >= 3 and inner[0] == 0x02:
                code = int.from_bytes(inner[2: 2 + inner[1]], "big")
                if code in (0xC000006D, 0xC000006E, 0xC0000064,
                            0xC000005E, 0xC0000192):
                    return False, (
                        f"RDP: login failed for '{domain}\\{user}' "
                        f"(errorCode=0x{code:X})"
                    )

        # pubKeyAuth echo from server is context tag [3] = 0xA3
        if b"\xa3" in ts4:
            return True, f"RDP LOGIN OK as '{domain}\\{user}'"

        # No errorCode and no pubKeyAuth — treat as success if server responded
        if ts4:
            return True, f"RDP LOGIN OK as '{domain}\\{user}'"
        return False, f"RDP: empty response after auth for '{domain}\\{user}'"

    except ssl.SSLError as e:
        return False, f"RDP TLS error: {e}"
    except socket.timeout:
        return False, "RDP: connection timed out"
    except ConnectionRefusedError:
        return False, "RDP: connection refused"
    except OSError as e:
        return False, f"RDP: {e}"


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
            service.get("imap_user", "jsmith"),
            service.get("imap_pass", "Ludus2025!"),
        )
    elif ctype == "rdp_login":
        return check_rdp_login(
            host, port,
            service.get("rdp_domain", "ludus"),
            service.get("rdp_user", "jsmith"),
            service.get("rdp_pass", "Ludus2025!"),
        )
    elif ctype == "ssh":
        return check_ssh(host, port)
    else:
        return False, f"Unknown check type: {ctype}"
