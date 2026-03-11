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


def check_ftp(host, port, user=None, password=None):
    """
    FTP deep check: attempt login with provided credentials.
    If user is "anonymous" (or no credentials set), uses anonymous login.
    If explicit credentials are set, performs authenticated login — a failed
    auth returns DOWN so the scorer knows to update the credentials.
    """
    use_anon = not user or user.lower() == "anonymous"
    login_user = "anonymous" if use_anon else user
    login_pass = ("scoring@ccdc.test" if use_anon else password) or ""
    try:
        ftp = ftplib.FTP(timeout=TIMEOUT)
        ftp.connect(host, port, timeout=TIMEOUT)
        banner = ftp.getwelcome()
        try:
            ftp.login(login_user, login_pass)
            ftp.quit()
            label = "Anonymous" if use_anon else f"'{login_user}'"
            return True, f"FTP login OK as {label} | {banner[:50]}"
        except ftplib.error_perm as e:
            try:
                ftp.quit()
            except Exception:
                pass
            err = str(e)
            if not use_anon:
                # Authenticated login failed — credentials are wrong or account locked
                return False, f"FTP login failed for '{login_user}': {err[:70]}"
            # Anonymous refused cases:
            # vsftpd OOPS — daemon running but chroot misconfigured
            if "500" in err and "OOPS" in err:
                return True, f"FTP UP (vsftpd chroot config issue) | {banner[:50]}"
            # Any other refusal means anonymous is disabled but service is alive
            return True, f"FTP UP (anonymous disabled) | {banner[:55]}"
    except ftplib.all_errors as e:
        return False, f"FTP error: {e}"
    except Exception as e:
        return False, str(e)


def check_smtp(host, port):
    """
    SMTP check via raw socket: connect, read the 220 greeting, send EHLO,
    and verify a 250 response.

    Uses a raw socket (same pattern as check_banner / check_imap_login)
    rather than smtplib for two reasons:
      1. smtplib sends QUIT in its teardown path; if Postfix has already
         closed or rate-limited the connection, smtplib raises
         SMTPServerDisconnected — a false negative.
      2. The EHLO hostname "scoring.ccdc.test" is unresolvable; Postfix
         configured with reject_unknown_helo_hostname rejects it.
    Closing the raw socket sends a clean TCP FIN that Postfix handles
    gracefully without needing a QUIT command.
    """
    try:
        with _tcp_connect(host, port) as s:
            # Read the server greeting — Postfix always opens with 220
            data = s.recv(2048)
            if not data:
                return False, "SMTP: no response from server"
            banner = data.decode("utf-8", errors="replace")
            if not banner.startswith("220"):
                return False, f"SMTP: expected 220, got: {banner[:60]}"
            first_line = banner.splitlines()[0].strip()

            # Use the range mail domain so Postfix HELO validation passes
            s.sendall(b"EHLO scoring.ludus.domain\r\n")
            data = s.recv(2048)
            if not data:
                return False, "SMTP: no EHLO response"
            ehlo = data.decode("utf-8", errors="replace")
            if not ehlo.startswith("250"):
                return False, f"SMTP EHLO failed: {ehlo[:60]}"

            return True, f"SMTP OK | {first_line[:60]}"
    except socket.timeout:
        return False, "SMTP: connection timed out"
    except ConnectionRefusedError:
        return False, "SMTP: connection refused"
    except Exception as e:
        return False, f"SMTP: {e}"


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
# Full RDP Network Level Authentication handshake:
#   TCP → X.224 (COTP) → TLS → CredSSP v5 (NTLM NEGOTIATE → CHALLENGE →
#   AUTHENTICATE + pubKeyAuth) — confirms a domain account can actually
#   authenticate to the workstation, not just that port 3389 is open.
#
# CredSSP v5 (Windows 10 1703+ / Server 2016+ post CVE-2018-0886 patch)
# uses a SHA-256 hash of the server TLS cert for pubKeyAuth.

def _md4(data: bytes) -> bytes:
    """Pure-Python MD4 (RFC 1320). Fallback for OpenSSL 3.x that removed MD4."""
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
        for i in range(16):
            t = _rol((a + _f(b, c, d) + X[i]) & M, [3, 7, 11, 19][i % 4])
            a, b, c, d = d, t, b, c
        for i in range(16):
            t = _rol((a + _g(b, c, d) + X[[0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15][i]] + 0x5A827999) & M, [3,5,9,13][i%4])
            a, b, c, d = d, t, b, c
        for i in range(16):
            t = _rol((a + _h(b, c, d) + X[[0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15][i]] + 0x6ED9EBA1) & M, [3,9,11,15][i%4])
            a, b, c, d = d, t, b, c
        A = (A+a)&M; B = (B+b)&M; C = (C+c)&M; D = (D+d)&M
    return struct.pack("<4I", A, B, C, D)


def _nt_hash(password: str) -> bytes:
    pw = password.encode("utf-16-le")
    try:
        return hashlib.new("md4", pw).digest()
    except ValueError:
        return _md4(pw)


def _rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i+1)%256; j = (j+S[i])%256; S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i]+S[j])%256])
    return bytes(out)


def _hmac_md5(key, msg): return _hmac_mod.new(key, msg, hashlib.md5).digest()
def _hmac_sha256(key, msg): return _hmac_mod.new(key, msg, hashlib.sha256).digest()


def _ntlm_negotiate() -> bytes:
    flags = (0x00000001|0x00000200|0x00008000|0x00020000|
             0x00080000|0x20000000|0x40000000|0x80000000)
    return (b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", flags)
            + b"\x00"*8 + b"\x00"*8 + b"\x06\x01\x00\x00\x00\x00\x00\x0f")


def _ntlm_authenticate(domain, user, password, server_challenge, target_info):
    nt_h = _nt_hash(password)
    rk = _hmac_md5(nt_h, (user.upper() + domain).encode("utf-16-le"))
    cc = os.urandom(8)
    ts = struct.pack("<Q", int((time.time()+11644473600)*10_000_000))
    blob = b"\x01\x01\x00\x00\x00\x00\x00\x00" + ts + cc + b"\x00\x00\x00\x00" + target_info + b"\x00\x00\x00\x00"
    nt_proof = _hmac_md5(rk, server_challenge + blob)
    nt_resp = nt_proof + blob
    sbk = _hmac_md5(rk, nt_proof)
    esk = os.urandom(16)
    enc_esk = _rc4(sbk, esk)
    flags = 0x00000001|0x00000200|0x00008000|0x00020000|0x00080000|0x20000000|0x40000000|0x80000000
    domain_b = domain.encode("utf-16-le"); user_b = user.encode("utf-16-le")
    ws_b = b"KALI\x00\x00\x00\x00"; lm = b"\x00"*24
    off = 88
    def fld(d):
        nonlocal off; f = struct.pack("<HHI", len(d), len(d), off); off += len(d); return f
    lmf=fld(lm); ntf=fld(nt_resp); df=fld(domain_b); uf=fld(user_b); wf=fld(ws_b); ef=fld(enc_esk)
    msg = (b"NTLMSSP\x00" + struct.pack("<I",3) + lmf+ntf+df+uf+wf+ef
           + struct.pack("<I",flags) + b"\x06\x01\x00\x00\x00\x00\x00\x0f" + b"\x00"*16
           + lm + nt_resp + domain_b + user_b + ws_b + enc_esk)
    return msg, esk


def _credssp_pub_key_auth(session_key, cert_der, client_nonce):
    bk = _hmac_sha256(session_key, b"CredSSP Client-To-Server Binding Hash\x00")
    return _hmac_sha256(bk, hashlib.sha256(cert_der).digest() + client_nonce)


def _der_len(n):
    if n < 0x80: return bytes([n])
    if n < 0x100: return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])

def _tlv(tag, data): return bytes([tag]) + _der_len(len(data)) + data

def _ts_req1(ntlm_neg, nonce):
    ver = _tlv(0xA0, _tlv(0x02, b"\x06"))
    nego = _tlv(0xA1, _tlv(0x30, _tlv(0x30, _tlv(0xA0, _tlv(0x04, ntlm_neg)))))
    return _tlv(0x30, ver + nego + _tlv(0xA5, _tlv(0x04, nonce)))

def _ts_req3(ntlm_auth, pka):
    ver = _tlv(0xA0, _tlv(0x02, b"\x06"))
    nego = _tlv(0xA1, _tlv(0x30, _tlv(0x30, _tlv(0xA0, _tlv(0x04, ntlm_auth)))))
    return _tlv(0x30, ver + nego + _tlv(0xA3, _tlv(0x04, pka)))

def _read_der(sock):
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4-len(hdr))
        if not chunk: return hdr
        hdr += chunk
    if hdr[0] != 0x30: return hdr + sock.recv(4096)
    b1 = hdr[1]
    total = (2+b1 if b1 < 0x80 else 3+hdr[2] if b1==0x81 else 4+(hdr[2]<<8|hdr[3]))
    data = hdr
    while len(data) < total:
        chunk = sock.recv(min(total-len(data), 8192))
        if not chunk: break
        data += chunk
    return data

def _extract_ntlm(ts_req):
    idx = ts_req.find(b"NTLMSSP\x00")
    if idx < 0: return b""
    for i in range(max(0, idx-4), idx):
        if ts_req[i] != 0x04: continue
        pos = i+1; b0 = ts_req[pos]
        if b0 < 0x80: return ts_req[i+2:i+2+b0]
        if b0 == 0x81: return ts_req[i+3:i+3+ts_req[pos+1]]
        if b0 == 0x82: return ts_req[i+4:i+4+((ts_req[pos+1]<<8)|ts_req[pos+2])]
    return ts_req[idx:]


def check_rdp_login(host, port, domain, user, password):
    """RDP NLA (CredSSP v5 / NTLMv2) authentication check."""
    x224_req = (b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00"
                b"\x01\x00\x08\x00\x03\x00\x00\x00")
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        sock.sendall(x224_req)
        resp = sock.recv(1024)
        if not resp or resp[0] != 0x03:
            sock.close()
            return False, "RDP: no valid X.224 response"
        if len(resp) >= 19 and resp[5] == 0xD0 and resp[11] == 0x02:
            sel = struct.unpack_from("<I", resp, 15)[0]
            if sel not in (0x02, 0x03):
                sock.close()
                return False, f"RDP: NLA not available (server selected 0x{sel:x})"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(sock, server_hostname=host)
        cert = tls.getpeercert(binary_form=True)
        nonce = os.urandom(32)
        tls.sendall(_ts_req1(_ntlm_negotiate(), nonce))
        ts2 = _read_der(tls)
        chal = _extract_ntlm(ts2)
        if len(chal) < 32 or chal[8:12] != b"\x02\x00\x00\x00":
            tls.close()
            return False, "RDP: expected NTLM CHALLENGE"
        srv_chal = chal[24:32]
        ti_len, _, ti_off = struct.unpack_from("<HHI", chal, 40)
        target_info = chal[ti_off:ti_off+ti_len]
        auth_msg, session_key = _ntlm_authenticate(domain, user, password, srv_chal, target_info)
        pka = _credssp_pub_key_auth(session_key, cert, nonce)
        tls.sendall(_ts_req3(auth_msg, pka))
        try:
            tls.settimeout(6)
            ts4 = _read_der(tls)
        except (ssl.SSLError, OSError):
            tls.close()
            return False, f"RDP: auth rejected for '{domain}\\{user}'"
        except socket.timeout:
            tls.close()
            return False, "RDP: timed out waiting for auth response"
        tls.close()
        if b"\xa4" in ts4:
            ei = ts4.index(b"\xa4"); inner = ts4[ei+2:]
            if len(inner) >= 3 and inner[0] == 0x02:
                code = int.from_bytes(inner[2:2+inner[1]], "big")
                if code in (0xC000006D, 0xC000006E, 0xC0000064, 0xC000005E, 0xC0000192):
                    return False, f"RDP: login failed for '{domain}\\{user}' (0x{code:X})"
        if b"\xa3" in ts4 or ts4:
            return True, f"RDP LOGIN OK as '{domain}\\{user}'"
        return False, f"RDP: empty response for '{domain}\\{user}'"
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

    # Effective credentials — set by app.py after merging DB overrides over defaults
    eff_user = service.get("_user")
    eff_pass = service.get("_pass")

    if ctype == "tcp":
        return check_tcp(host, port)
    elif ctype == "http":
        return check_http(host, port)
    elif ctype == "ftp":
        return check_ftp(host, port, eff_user, eff_pass)
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
        return check_imap_login(host, port, eff_user, eff_pass)
    elif ctype == "rdp_login":
        return check_rdp_login(
            host, port,
            service.get("rdp_domain", "ludus"),
            eff_user or service.get("default_user", "jsmith"),
            eff_pass or service.get("default_pass", ""),
        )
    elif ctype == "ssh":
        return check_ssh(host, port)
    else:
        return False, f"Unknown check type: {ctype}"
