#!/usr/bin/env bash
# start.sh — launch the CCDC Blue Team Scoring Engine on Kali
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Require Python 3.8+
python3 -c "import sys; assert sys.version_info >= (3,8), 'Python 3.8+ required'" \
  || { echo "ERROR: Python 3.8 or higher is required."; exit 1; }

# Install / upgrade dependencies quietly
echo "[*] Installing Python dependencies..."
pip3 install -q --upgrade -r requirements.txt

# Print detected range info before starting
python3 - <<'EOF'
import config
print(f"[*] Detected Range ID : {config.RANGE_ID}")
print(f"[*] Target network    : {config.BASE_NET}.0/24")
print(f"[*] Check interval    : {config.CHECK_INTERVAL}s")
print(f"[*] Services checked  : {len(config.SERVICES)}")
print(f"[*] Max pts / round   : {config.MAX_SCORE_PER_ROUND}")
EOF

echo ""
echo "[*] Starting scoring engine..."
echo "[*] Dashboard → http://$(hostname -I | awk '{print $1}'):8080/"
echo ""

exec python3 app.py
