#!/usr/bin/env python3
"""Generate network_diagram.png for the CIS 405 final paper."""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

# ── figure ────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(14, 11))
ax.set_xlim(0, 14)
ax.set_ylim(0, 11)
ax.axis("off")

# ── palette ───────────────────────────────────────────────────────────────────
C_INTERNET  = "#e8f4f8"
C_ROUTER    = "#fff3cd"
C_VLAN10_BG = "#e8f0fe"
C_VLAN99_BG = "#fce8e8"
C_CORP      = "#c6d9f7"
C_ATK       = "#f7c6c6"
C_EDGE      = "#555555"
C_TITLE10   = "#1a56db"
C_TITLE99   = "#c0392b"

FONT = "DejaVu Sans"


def box(ax, x, y, w, h, label_lines, bg, edge=C_EDGE, fontsize=8.5,
        title_color="black", bold_first=True):
    """Draw a rounded rectangle with multi-line text inside."""
    rect = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.04",
        facecolor=bg, edgecolor=edge, linewidth=1.2, zorder=2
    )
    ax.add_patch(rect)
    cx = x + w / 2
    cy = y + h / 2
    n = len(label_lines)
    step = min(h / (n + 1), 0.27)
    top_y = cy + step * (n - 1) / 2
    for i, line in enumerate(label_lines):
        bold = bold_first and i == 0
        color = title_color if (bold_first and i == 0) else "black"
        ax.text(cx, top_y - i * step, line,
                ha="center", va="center",
                fontsize=fontsize,
                fontweight="bold" if bold else "normal",
                color=color,
                fontfamily=FONT, zorder=3)


def arrow(ax, x1, y1, x2, y2, color="#555555", lw=1.5):
    ax.annotate("",
        xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(arrowstyle="-|>", color=color, lw=lw),
        zorder=1)
    ax.annotate("",
        xy=(x1, y1), xytext=(x2, y2),
        arrowprops=dict(arrowstyle="-|>", color=color, lw=lw),
        zorder=1)


def line(ax, x1, y1, x2, y2, color="#555555", lw=1.4, style="-"):
    ax.plot([x1, x2], [y1, y2], color=color, lw=lw, linestyle=style, zorder=1)


# ── internet ──────────────────────────────────────────────────────────────────
box(ax, 5.2, 9.4, 3.6, 0.7,
    ["INTERNET / WAN"],
    bg=C_INTERNET, fontsize=10, bold_first=True, title_color="#1a6e1a")

# ── router ────────────────────────────────────────────────────────────────────
box(ax, 5.25, 7.85, 3.5, 0.8,
    ["Debian Router", "10.X.1.254  |  Proxmox Host"],
    bg=C_ROUTER, fontsize=9)

# internet to router
arrow(ax, 7.0, 9.4, 7.0, 8.65)

# ── VLAN 10 background ────────────────────────────────────────────────────────
box(ax, 0.3, 0.3, 5.9, 7.3,
    [], bg=C_VLAN10_BG, edge=C_TITLE10, fontsize=10)
ax.text(3.25, 7.45, "VLAN 10  \u2014  Corporate Network  \u2014  10.X.10.0/24",
        ha="center", va="bottom", fontsize=9.5, fontweight="bold",
        color=C_TITLE10, fontfamily=FONT, zorder=4)

# ── VLAN 99 background ────────────────────────────────────────────────────────
box(ax, 7.8, 0.3, 5.9, 7.3,
    [], bg=C_VLAN99_BG, edge=C_TITLE99, fontsize=10)
ax.text(10.75, 7.45, "VLAN 99  \u2014  Attacker Network  \u2014  10.X.99.0/24",
        ha="center", va="bottom", fontsize=9.5, fontweight="bold",
        color=C_TITLE99, fontfamily=FONT, zorder=4)

# router to VLANs
line(ax, 5.9, 7.85, 3.25, 7.6)
line(ax, 8.1, 7.85, 10.75, 7.6)

# ── VLAN 10 VMs ───────────────────────────────────────────────────────────────
VMS_10 = [
    ("DC01",     "10.X.10.11", "Windows Server 2022", "Domain Controller",   "Ports: 53, 88, 389, 445, 636"),
    ("PC01",     "10.X.10.21", "Windows 11 Ent.",     "Workstation",         "Domain joined"),
    ("WEB01",    "10.X.10.31", "Ubuntu 22.04",        "Web Server",          "Ports: 80, 443"),
    ("DB01",     "10.X.10.41", "Debian 12",           "Database Server",     "Port: 3306"),
    ("FILESVR",  "10.X.10.51", "Windows Server 2022", "File Server",         "Port: 445 (SMB)"),
    ("MAIL01",   "10.X.10.61", "Debian 12",           "Mail Server",         "Ports: 25, 110, 143"),
    ("FTP01",    "10.X.10.81", "Ubuntu 22.04",        "FTP Server",          "Port: 21"),
]

vm_w = 5.5
vm_h = 0.82
gap  = 0.18
total_h = len(VMS_10) * vm_h + (len(VMS_10) - 1) * gap
start_y = 0.45 + total_h - vm_h   # top box y

for i, (host, ip, os_, role, ports) in enumerate(VMS_10):
    y = start_y - i * (vm_h + gap)
    box(ax, 0.5, y, vm_w, vm_h,
        [host, ip, os_, role, ports],
        bg=C_CORP, fontsize=8, title_color=C_TITLE10)

# ── VLAN 99 VMs ───────────────────────────────────────────────────────────────
VMS_99 = [
    ("Kali-1",  "10.X.99.1",  "Kali Linux",     "Attacker / Red Team",    "Full kali linux default toolset"),
    ("SCORE01", "10.X.99.10", "Ubuntu 22.04",   "Scoring Engine",          "Port: 8080 (web dashboard)"),
]

vm_w2 = 5.5
vm_h2 = 1.15
gap2  = 0.5
total_h2 = len(VMS_99) * vm_h2 + (len(VMS_99) - 1) * gap2
start_y2 = (7.6 - 0.45) / 2 + 0.45 + total_h2 / 2 - vm_h2

for i, (host, ip, os_, role, ports) in enumerate(VMS_99):
    y = start_y2 - i * (vm_h2 + gap2)
    box(ax, 8.0, y, vm_w2, vm_h2,
        [host, ip, os_, role, ports],
        bg=C_ATK, fontsize=9, title_color=C_TITLE99)

# ── firewall note ─────────────────────────────────────────────────────────────
ax.text(7.0, 3.8,
        "VLAN 10 \u2192 VLAN 99:\n ports 80, 443, 8080 only\n\nVLAN 99 \u2192 VLAN 10:\n all ports allowed",
        ha="center", va="center", fontsize=7.8, color="#555555",
        style="italic", fontfamily=FONT,
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                  edgecolor="#aaaaaa", linewidth=0.8), zorder=5)

# ── title ─────────────────────────────────────────────────────────────────────
ax.text(7.0, 10.75,
        "CCDC Practice Range Network Diagram",
        ha="center", va="center", fontsize=12, fontweight="bold",
        color="#222222", fontfamily=FONT)

plt.tight_layout(pad=0)
plt.savefig("network_diagram.png", dpi=180, bbox_inches="tight",
            facecolor="white")
print("Saved: network_diagram.png")
