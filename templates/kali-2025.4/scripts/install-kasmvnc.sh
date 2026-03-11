#!/bin/bash
# Install and configure KasmVNC for Kali Linux.
# Ludus provides web-based GUI access via https://<vm-ip>:8444
#
# Port math: KasmVNC HTTPS base port (8443) + display number (:1) = 8444
#
# If this script fails during template build, comment out the KasmVNC
# provisioner block in kali-2025.4.pkr.hcl and install KasmVNC manually
# or via an Ansible role after deployment.
#
# Called by Packer as root (execute_command uses sudo sh -c).
set -ex

export DEBIAN_FRONTEND=noninteractive

# ─── Version ──────────────────────────────────────────────────────────────────
# Verify this release exists at:
# https://github.com/kasmtech/KasmVNC/releases
KASMVNC_VERSION="1.3.3"
KASMVNC_DEB="kasmvncserver_kali_rolling_${KASMVNC_VERSION}_amd64.deb"
KASMVNC_URL="https://github.com/kasmtech/KasmVNC/releases/download/v${KASMVNC_VERSION}/${KASMVNC_DEB}"

# ─── Dependencies ─────────────────────────────────────────────────────────────
apt-get update -y
apt-get install -y \
    libturbojpeg0 \
    libxfont2 \
    libxshmfence1 \
    libgbm1 \
    wget

# ─── Download & install ───────────────────────────────────────────────────────
cd /tmp
wget -q -O "${KASMVNC_DEB}" "${KASMVNC_URL}"
apt-get install -y "./${KASMVNC_DEB}"
rm -f "${KASMVNC_DEB}"

# ─── Configure VNC password for kali user ────────────────────────────────────
# Sets the web-access password to "password" (Ludus convention).
# The "n" at the end declines the view-only password prompt.
mkdir -p /home/kali/.vnc
printf 'password\npassword\nn\n' | kasmvncpasswd -u kali -w -r
chown -R kali:kali /home/kali/.vnc

# ─── Systemd service ──────────────────────────────────────────────────────────
# Starts KasmVNC on display :1 using XFCE when the VM boots.
# HTTPS listens on 8443 + 1 = 8444.
cat > /etc/systemd/system/kasmvnc.service << 'UNIT'
[Unit]
Description=KasmVNC remote desktop server
After=network.target graphical.target

[Service]
Type=simple
User=kali
Environment=DISPLAY=:1
ExecStartPre=/bin/sh -c 'vncserver -kill :1 > /dev/null 2>&1 || true'
ExecStart=/usr/bin/vncserver :1 -select-de xfce -SecurityTypes VncAuth,TLSVnc
ExecStop=/usr/bin/vncserver -kill :1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable kasmvnc

# ─── Firewall ─────────────────────────────────────────────────────────────────
# Open port 8444 if ufw is active (it is disabled by default in Kali)
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow 8444/tcp
fi
