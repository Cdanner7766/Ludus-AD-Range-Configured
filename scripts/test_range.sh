#!/usr/bin/env bash
# =============================================================================
# CCDC Range Validation Script
# Run from the Kali VM after deployment to verify all services are operational.
#
# Usage:
#   ./test_range.sh              # Auto-detect range base from Kali's IP
#   ./test_range.sh 10.2.10      # Manually specify VLAN 10 network base
# =============================================================================

set -o pipefail

# --- Color output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { ((PASS++)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { ((FAIL++)); echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { ((WARN++)); echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }
header() { echo -e "\n${BOLD}=== $1 ===${NC}"; }

# --- Determine network base ---
if [ -n "$1" ]; then
    BASE="$1"
else
    # Auto-detect: Kali is on VLAN 99, services are on VLAN 10
    # Kali IP is 10.X.99.1, so services are at 10.X.10.*
    KALI_IP=$(ip -4 addr show | grep -oP '10\.\d+\.99\.\d+' | head -1)
    if [ -z "$KALI_IP" ]; then
        echo -e "${RED}ERROR: Could not auto-detect Kali IP on VLAN 99.${NC}"
        echo "Usage: $0 <network-base>  (e.g., $0 10.2.10)"
        exit 1
    fi
    RANGE_OCTET=$(echo "$KALI_IP" | cut -d. -f2)
    BASE="10.${RANGE_OCTET}.10"
    echo -e "${CYAN}Auto-detected Kali IP: ${KALI_IP}${NC}"
fi

# --- VM IPs ---
DC="${BASE}.11"
PC01="${BASE}.21"
WEB="${BASE}.31"
DB="${BASE}.41"
FILE="${BASE}.51"
MAIL="${BASE}.61"
DNS="${BASE}.71"
FTP="${BASE}.81"

echo -e "${BOLD}CCDC Range Validation${NC}"
echo -e "Network base: ${CYAN}${BASE}.0/24${NC}"
echo -e "Timestamp:    $(date)"

# --- Helper: check TCP port ---
check_port() {
    local host=$1 port=$2 timeout=${3:-5}
    nc -z -w "$timeout" "$host" "$port" 2>/dev/null
}

# =============================================================================
header "1. NETWORK CONNECTIVITY (Ping)"
# =============================================================================
declare -A HOSTS=(
    ["DC (${DC})"]="$DC"
    ["PC01 (${PC01})"]="$PC01"
    ["WEB01 (${WEB})"]="$WEB"
    ["DB01 (${DB})"]="$DB"
    ["FILESVR (${FILE})"]="$FILE"
    ["MAIL01 (${MAIL})"]="$MAIL"
    ["DNS01 (${DNS})"]="$DNS"
    ["FTP01 (${FTP})"]="$FTP"
)

for name in "DC (${DC})" "PC01 (${PC01})" "WEB01 (${WEB})" "DB01 (${DB})" "FILESVR (${FILE})" "MAIL01 (${MAIL})" "DNS01 (${DNS})" "FTP01 (${FTP})"; do
    ip="${HOSTS[$name]}"
    if ping -c 1 -W 3 "$ip" &>/dev/null; then
        pass "$name - reachable"
    else
        fail "$name - unreachable"
    fi
done

# =============================================================================
header "2. WEB SERVER (${WEB}) - Apache + PHP"
# =============================================================================

# Port 80
if check_port "$WEB" 80; then
    pass "Port 80/tcp open"
else
    fail "Port 80/tcp closed"
fi

# HTTP response
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 "http://${WEB}/" 2>/dev/null)
if [ "$HTTP_CODE" = "200" ]; then
    pass "HTTP 200 OK from index page"
else
    fail "HTTP response: ${HTTP_CODE:-timeout} (expected 200)"
fi

# Check index page content
if curl -s --connect-timeout 5 "http://${WEB}/" 2>/dev/null | grep -q "CCDC Practice"; then
    pass "Index page contains expected content"
else
    fail "Index page missing expected content"
fi

# phpinfo page (vulnerability check)
if curl -s --connect-timeout 5 "http://${WEB}/info.php" 2>/dev/null | grep -qi "phpinfo"; then
    pass "info.php accessible (VULN: information disclosure)"
else
    fail "info.php not accessible"
fi

# Directory listing (vulnerability check)
HEADERS=$(curl -sI --connect-timeout 5 "http://${WEB}/" 2>/dev/null)
if echo "$HEADERS" | grep -qi "Apache"; then
    pass "Server header exposes Apache version (VULN: ServerTokens Full)"
else
    warn "Server header not detected"
fi

# =============================================================================
header "3. DATABASE SERVER (${DB}) - MariaDB/MySQL"
# =============================================================================

# Port 3306
if check_port "$DB" 3306; then
    pass "Port 3306/tcp open"
else
    fail "Port 3306/tcp closed"
fi

# MySQL login with weak credentials
if command -v mysql &>/dev/null; then
    if mysql -h "$DB" -u root -ppassword -e "SELECT 1;" &>/dev/null; then
        pass "MySQL root login with weak password (VULN: root/password)"
    else
        fail "MySQL root login failed"
    fi

    if mysql -h "$DB" -u admin -padmin -e "SELECT 1;" &>/dev/null; then
        pass "MySQL admin login with weak password (VULN: admin/admin)"
    else
        fail "MySQL admin login failed"
    fi

    # Check sample database
    if mysql -h "$DB" -u root -ppassword -e "USE ccdc_company; SELECT * FROM employees;" &>/dev/null; then
        pass "ccdc_company database with employee data accessible"
    else
        fail "ccdc_company database not accessible"
    fi
else
    info "mysql client not installed - install with: sudo apt install -y default-mysql-client"
    # Fallback: just check the banner
    BANNER=$(echo "" | nc -w 3 "$DB" 3306 2>/dev/null | strings 2>/dev/null | head -1)
    if [ -n "$BANNER" ]; then
        pass "MySQL banner received: ${BANNER:0:60}"
    else
        warn "Could not read MySQL banner (install mysql client for full test)"
    fi
fi

# =============================================================================
header "4. FILE SERVER (${FILE}) - SMB Shares"
# =============================================================================

# Port 445
if check_port "$FILE" 445; then
    pass "Port 445/tcp open (SMB)"
else
    fail "Port 445/tcp closed (SMB)"
fi

# Port 139 (SMBv1/NetBIOS)
if check_port "$FILE" 139; then
    pass "Port 139/tcp open (NetBIOS/SMBv1)"
else
    warn "Port 139/tcp closed (SMBv1 may not be fully active yet)"
fi

# List shares with anonymous/guest access
if command -v smbclient &>/dev/null; then
    SHARES=$(smbclient -L "//${FILE}" -N 2>/dev/null)
    if echo "$SHARES" | grep -qi "Public"; then
        pass "Public share visible via anonymous listing (VULN: guest access)"
    else
        fail "Public share not visible"
    fi

    if echo "$SHARES" | grep -qi "Shared"; then
        pass "Shared share visible via anonymous listing"
    else
        fail "Shared share not visible"
    fi

    # Try reading a file from Public share
    FILE_CONTENT=$(smbclient "//${FILE}/Public" -N -c "get readme.txt -" 2>/dev/null)
    if echo "$FILE_CONTENT" | grep -qi "CCDC"; then
        pass "Can read files from Public share anonymously (VULN: Everyone Full Control)"
    else
        warn "Could not read Public share files (may need domain context)"
    fi
else
    info "smbclient not installed - install with: sudo apt install -y smbclient"
fi

# =============================================================================
header "5. MAIL SERVER (${MAIL}) - Postfix + Dovecot"
# =============================================================================

# SMTP (25)
if check_port "$MAIL" 25; then
    pass "Port 25/tcp open (SMTP)"
else
    fail "Port 25/tcp closed (SMTP)"
fi

# IMAP (143)
if check_port "$MAIL" 143; then
    pass "Port 143/tcp open (IMAP)"
else
    fail "Port 143/tcp closed (IMAP)"
fi

# POP3 (110)
if check_port "$MAIL" 110; then
    pass "Port 110/tcp open (POP3)"
else
    fail "Port 110/tcp closed (POP3)"
fi

# SMTP banner
SMTP_BANNER=$(echo "QUIT" | nc -w 5 "$MAIL" 25 2>/dev/null | head -1)
if echo "$SMTP_BANNER" | grep -qi "ESMTP"; then
    pass "SMTP banner: ${SMTP_BANNER:0:70}"
else
    fail "No SMTP banner received"
fi

# Test open relay: SMTP accepts RCPT TO for external domain
RELAY_TEST=$(printf "HELO test\r\nMAIL FROM:<test@attacker.com>\r\nRCPT TO:<anyone@external.com>\r\nQUIT\r\n" | nc -w 5 "$MAIL" 25 2>/dev/null)
if echo "$RELAY_TEST" | grep -q "250.*Ok\|250.*Recipient"; then
    pass "SMTP open relay confirmed (VULN: accepts mail for external domains)"
else
    warn "Open relay test inconclusive"
fi

# IMAP plaintext auth check
IMAP_BANNER=$(echo "" | nc -w 5 "$MAIL" 143 2>/dev/null | head -1)
if echo "$IMAP_BANNER" | grep -qi "Dovecot\|IMAP"; then
    pass "IMAP banner: ${IMAP_BANNER:0:70}"
else
    warn "No IMAP banner received"
fi

# =============================================================================
header "6. DNS SERVER (${DNS}) - Windows DNS"
# =============================================================================

# Port 53
if check_port "$DNS" 53; then
    pass "Port 53/tcp open (DNS)"
else
    fail "Port 53/tcp closed (DNS)"
fi

# DNS queries
if command -v dig &>/dev/null; then
    # Query for web.ludus.domain
    DIG_RESULT=$(dig @"$DNS" web.ludus.domain +short +time=5 2>/dev/null)
    if [ -n "$DIG_RESULT" ]; then
        pass "DNS resolves web.ludus.domain -> ${DIG_RESULT}"
    else
        fail "DNS did not resolve web.ludus.domain"
    fi

    # Query for mail.ludus.domain
    DIG_RESULT=$(dig @"$DNS" mail.ludus.domain +short +time=5 2>/dev/null)
    if [ -n "$DIG_RESULT" ]; then
        pass "DNS resolves mail.ludus.domain -> ${DIG_RESULT}"
    else
        fail "DNS did not resolve mail.ludus.domain"
    fi

    # MX record
    MX_RESULT=$(dig @"$DNS" ludus.domain MX +short +time=5 2>/dev/null)
    if [ -n "$MX_RESULT" ]; then
        pass "MX record: ${MX_RESULT}"
    else
        fail "No MX record for ludus.domain"
    fi

    # Zone transfer (vulnerability check)
    AXFR_RESULT=$(dig @"$DNS" ludus.domain AXFR +time=5 2>/dev/null)
    if echo "$AXFR_RESULT" | grep -q "web\|mail\|ftp"; then
        pass "Zone transfer (AXFR) allowed (VULN: full zone dump possible)"
    else
        warn "Zone transfer test inconclusive"
    fi
else
    info "dig not installed - install with: sudo apt install -y dnsutils"
fi

# =============================================================================
header "7. FTP SERVER (${FTP}) - vsftpd"
# =============================================================================

# Port 21
if check_port "$FTP" 21; then
    pass "Port 21/tcp open (FTP)"
else
    fail "Port 21/tcp closed (FTP)"
fi

# FTP banner
FTP_BANNER=$(echo "QUIT" | nc -w 5 "$FTP" 21 2>/dev/null | head -1)
if echo "$FTP_BANNER" | grep -qi "vsftpd\|FTP\|Welcome"; then
    pass "FTP banner: ${FTP_BANNER:0:70}"
else
    fail "No FTP banner received"
fi

# Anonymous login
if command -v ftp &>/dev/null || command -v lftp &>/dev/null; then
    ANON_TEST=$(curl -s --connect-timeout 5 "ftp://${FTP}/pub/readme.txt" 2>/dev/null)
    if echo "$ANON_TEST" | grep -qi "CCDC\|Public"; then
        pass "Anonymous FTP access works (VULN: anon read enabled)"
    else
        warn "Anonymous FTP read test inconclusive - try manually: curl ftp://${FTP}/pub/"
    fi

    # Check for credentials file
    CREDS_TEST=$(curl -s --connect-timeout 5 "ftp://${FTP}/pub/backup_notes.txt" 2>/dev/null)
    if echo "$CREDS_TEST" | grep -qi "credentials\|password"; then
        pass "Credentials file accessible via anonymous FTP (VULN: sensitive data exposed)"
    else
        warn "Credentials file not found via anonymous FTP"
    fi
else
    info "No FTP client available - install with: sudo apt install -y ftp"
fi

# =============================================================================
header "8. DOMAIN CONTROLLER (${DC})"
# =============================================================================

# Common DC ports
for port_desc in "53:DNS" "88:Kerberos" "389:LDAP" "445:SMB" "636:LDAPS"; do
    port=$(echo "$port_desc" | cut -d: -f1)
    desc=$(echo "$port_desc" | cut -d: -f2)
    if check_port "$DC" "$port"; then
        pass "Port ${port}/tcp open (${desc})"
    else
        fail "Port ${port}/tcp closed (${desc})"
    fi
done

# =============================================================================
header "9. NETWORK RULES (Kali -> VLAN 10 access)"
# =============================================================================
info "Kali (VLAN 99) should have full access to VLAN 10 per network rules"
info "VLAN 10 -> Kali should only work on ports 80, 443, 8080"

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo -e "${BOLD}============================================${NC}"
echo -e "${BOLD}              TEST SUMMARY                  ${NC}"
echo -e "${BOLD}============================================${NC}"
echo -e "  ${GREEN}PASSED:  ${PASS}${NC}"
echo -e "  ${RED}FAILED:  ${FAIL}${NC}"
echo -e "  ${YELLOW}WARNINGS: ${WARN}${NC}"
TOTAL=$((PASS + FAIL))
echo -e "  TOTAL:   ${TOTAL}"
echo -e "${BOLD}============================================${NC}"

if [ "$FAIL" -gt 0 ]; then
    echo -e "\n${RED}Some tests failed. Check the output above for details.${NC}"
    exit 1
else
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
fi
