#!/bin/bash
# Install the kali-linux-default metapackage.
# This pulls in the full XFCE desktop environment + standard Kali toolset.
# Expect ~60-90 minutes and 20-30 GB of downloads.
#
# Called by Packer as root (execute_command uses sudo sh -c).
set -ex

export DEBIAN_FRONTEND=noninteractive

# Refresh package lists against the Kali mirror
apt-get update -y

# Upgrade base system first to avoid dependency conflicts
apt-get full-upgrade -y

# Install the full default Kali toolset + XFCE desktop.
# kali-linux-default depends on kali-desktop-xfce, kali-tools-top10, etc.
apt-get install -y \
    kali-linux-default \
    kali-desktop-xfce

# Ensure python3 is available for Ansible (may already be present)
apt-get install -y python3 python3-pip

# Clean up to shrink the template image
apt-get autoremove -y
apt-get clean
rm -rf /var/lib/apt/lists/*
