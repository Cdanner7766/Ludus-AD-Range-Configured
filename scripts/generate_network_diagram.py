#!/usr/bin/env python3
"""
Generate a network topology diagram for the Ludus CCDC Practice Range.
Output: docs/network_diagram.png
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

# ── colour palette ────────────────────────────────────────────────────────────
C_VLAN10_BG  = "#e8f4fd"   # light blue
C_VLAN99_BG  = "#fde8e8"   # light red
C_WIN_BOX    = "#4472c4"   # Windows blue
C_LIN_BOX    = "#e26b0a"   # Linux orange
C_KALI_BOX   = "#7030a0"   # Kali purple
C_SCORE_BOX  = "#375623"   # Score green
C_FW_BOX     = "#c00000"   # Firewall red
C_ARROW_FW   = "#404040"
C_PORT_TXT   = "#1f3864"

FIG_W, FIG_H = 22, 14

# ── VM definitions ────────────────────────────────────────────────────────────
# (label, ip, ports_lines, colour, x, y)  — x/y in data coords
VLAN10_VMS = [
    {
        "label": "DC01-2022",
        "sub":   "Windows Server 2022\nDomain Controller",
        "ip":    "10.X.10.11",
        "ports": ["53/tcp+udp  DNS", "88/tcp      Kerberos", "389/tcp     LDAP", "445/tcp     SMB"],
        "color": C_WIN_BOX,
        "col":   0,
    },
    {
        "label": "PC01-W11",
        "sub":   "Windows 11 Enterprise\nWorkstation",
        "ip":    "10.X.10.21",
        "ports": ["3389/tcp    RDP"],
        "color": C_WIN_BOX,
        "col":   1,
    },
    {
        "label": "FILESVR",
        "sub":   "Windows Server 2022\nFile Server",
        "ip":    "10.X.10.51",
        "ports": ["139/tcp     NetBIOS", "445/tcp     SMB"],
        "color": C_WIN_BOX,
        "col":   2,
    },
    {
        "label": "WEB01",
        "sub":   "Ubuntu 22.04 Server\nApache 2 + PHP 8.1",
        "ip":    "10.X.10.31",
        "ports": ["80/tcp      HTTP"],
        "color": C_LIN_BOX,
        "col":   3,
    },
    {
        "label": "DB01",
        "sub":   "Debian 12 Server\nMariaDB",
        "ip":    "10.X.10.41",
        "ports": ["3306/tcp    MySQL"],
        "color": C_LIN_BOX,
        "col":   4,
    },
    {
        "label": "MAIL01",
        "sub":   "Debian 12 Server\nPostfix + Dovecot",
        "ip":    "10.X.10.61",
        "ports": ["25/tcp      SMTP", "110/tcp     POP3", "143/tcp     IMAP"],
        "color": C_LIN_BOX,
        "col":   5,
    },
    {
        "label": "FTP01",
        "sub":   "Ubuntu 22.04 Server\nvsftpd 3.0.5",
        "ip":    "10.X.10.81",
        "ports": ["21/tcp      FTP", "40000-40100 Passive"],
        "color": C_LIN_BOX,
        "col":   6,
    },
]

VLAN99_VMS = [
    {
        "label": "kali-1",
        "sub":   "Kali Linux\nRed Team",
        "ip":    "10.X.99.1",
        "ports": ["(all ports — attacker)"],
        "color": C_KALI_BOX,
        "col":   1,
    },
    {
        "label": "SCORE01",
        "sub":   "Ubuntu 22.04 + XFCE4\nScoring Engine",
        "ip":    "10.X.99.10",
        "ports": ["8080/tcp    Dashboard"],
        "color": C_SCORE_BOX,
        "col":   5,
    },
]

# ── layout constants ──────────────────────────────────────────────────────────
VM_W, VM_H   = 2.6, 2.4   # box size
VM_HGAP      = 0.45        # horizontal gap between boxes
V10_ROW_Y    = 7.5         # y of VLAN-10 VM top edge
V99_ROW_Y    = 1.8         # y of VLAN-99 VM top edge
VLAN_PAD     = 0.55        # padding around VM group for VLAN rectangle

NCOLS_10 = len(VLAN10_VMS)   # 7
TOTAL_W_10 = NCOLS_10 * VM_W + (NCOLS_10 - 1) * VM_HGAP  # total row width

# ── helpers ───────────────────────────────────────────────────────────────────

def vm_x(col, total_cols, row_width, fig_cx=FIG_W / 2):
    """Centre the VM grid on fig_cx."""
    start_x = fig_cx - row_width / 2
    return start_x + col * (VM_W + VM_HGAP)


def draw_vm(ax, x, y, vm):
    """Draw a VM box with label, IP, and ports."""
    # shadow
    ax.add_patch(FancyBboxPatch(
        (x + 0.06, y - 0.06), VM_W, VM_H,
        boxstyle="round,pad=0.08", linewidth=0,
        facecolor="#00000022", zorder=2,
    ))
    # main box
    ax.add_patch(FancyBboxPatch(
        (x, y), VM_W, VM_H,
        boxstyle="round,pad=0.08", linewidth=1.5,
        edgecolor=vm["color"], facecolor="white", zorder=3,
    ))
    # header band
    ax.add_patch(FancyBboxPatch(
        (x, y + VM_H - 0.55), VM_W, 0.55,
        boxstyle="round,pad=0.08", linewidth=0,
        facecolor=vm["color"], zorder=4,
    ))
    # hostname
    ax.text(x + VM_W / 2, y + VM_H - 0.275, vm["label"],
            ha="center", va="center", fontsize=9, fontweight="bold",
            color="white", zorder=5)
    # OS / service line
    ax.text(x + VM_W / 2, y + VM_H - 0.75, vm["sub"],
            ha="center", va="top", fontsize=6.5, color="#333333",
            linespacing=1.3, zorder=5)
    # IP address
    ax.text(x + VM_W / 2, y + 1.0, vm["ip"],
            ha="center", va="center", fontsize=8.5,
            fontfamily="monospace", color=C_PORT_TXT,
            fontweight="bold", zorder=5)
    # ports
    port_txt = "\n".join(vm["ports"])
    ax.text(x + 0.12, y + 0.82, port_txt,
            ha="left", va="top", fontsize=6.5,
            fontfamily="monospace", color="#444444",
            linespacing=1.5, zorder=5)


def vlan_rect(ax, x, y, w, h, label, color, text_color="white"):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.15", linewidth=2,
        edgecolor=color, facecolor=color + "22", zorder=1,
    ))
    ax.text(x + 0.2, y + h - 0.22, label,
            ha="left", va="top", fontsize=10, fontweight="bold",
            color=color, zorder=2)


# ── figure ────────────────────────────────────────────────────────────────────

fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
ax.set_xlim(0, FIG_W)
ax.set_ylim(0, FIG_H)
ax.axis("off")
fig.patch.set_facecolor("#f7f8fa")

# ── title ─────────────────────────────────────────────────────────────────────
ax.text(FIG_W / 2, FIG_H - 0.35,
        "Ludus CCDC Practice Range — Network Topology",
        ha="center", va="top", fontsize=14, fontweight="bold", color="#1f1f1f")
ax.text(FIG_W / 2, FIG_H - 0.75,
        "Network: 10.X.0.0/16  |  X = Ludus Range ID (auto-detected at deploy time)",
        ha="center", va="top", fontsize=9, color="#555555")

# ── VLAN 10 background ────────────────────────────────────────────────────────
v10_x0 = vm_x(0, NCOLS_10, TOTAL_W_10) - VLAN_PAD
v10_y0 = V10_ROW_Y - VLAN_PAD
v10_w  = TOTAL_W_10 + 2 * VLAN_PAD
v10_h  = VM_H + 2 * VLAN_PAD + 0.1

vlan_rect(ax, v10_x0, v10_y0, v10_w, v10_h,
          "VLAN 10 — Corporate Network  (10.X.10.0/24)", "#2e75b6")

# ── VLAN 99 background ────────────────────────────────────────────────────────
NCOLS_99   = 7   # use same width as VLAN-10 for alignment
TOTAL_W_99 = TOTAL_W_10

v99_x0 = v10_x0
v99_y0 = V99_ROW_Y - VLAN_PAD
v99_w  = v10_w
v99_h  = VM_H + 2 * VLAN_PAD + 0.1

vlan_rect(ax, v99_x0, v99_y0, v99_w, v99_h,
          "VLAN 99 — Attacker Network  (10.X.99.0/24)", "#c00000")

# ── FIREWALL banner ───────────────────────────────────────────────────────────
fw_y = (V10_ROW_Y - VLAN_PAD) - 0.05     # just below VLAN-10 bottom
fw_top = V99_ROW_Y + VM_H + VLAN_PAD + 0.1  # just above VLAN-99 top
fw_mid = (fw_y + fw_top) / 2

ax.add_patch(FancyBboxPatch(
    (v10_x0 + 0.5, fw_mid - 0.38), v10_w - 1.0, 0.76,
    boxstyle="round,pad=0.1", linewidth=2,
    edgecolor=C_FW_BOX, facecolor="#ffe0e0", zorder=6,
))
ax.text(FIG_W / 2, fw_mid + 0.22,
        "FIREWALL  (Ludus inter-VLAN rules)", ha="center", va="center",
        fontsize=9, fontweight="bold", color=C_FW_BOX, zorder=7)
ax.text(FIG_W / 2, fw_mid - 0.15,
        "VLAN10→99: TCP 80, 443, 8080 only   |   VLAN99→10: ALL protocols, ALL ports",
        ha="center", va="center", fontsize=8, color="#600000", zorder=7)

# ── draw VLAN-10 VMs ─────────────────────────────────────────────────────────
for vm in VLAN10_VMS:
    x = vm_x(vm["col"], NCOLS_10, TOTAL_W_10)
    draw_vm(ax, x, V10_ROW_Y, vm)

# ── draw VLAN-99 VMs ─────────────────────────────────────────────────────────
# Place kali-1 on left, SCORE01 on right — match column widths of VLAN-10
for vm in VLAN99_VMS:
    x = vm_x(vm["col"], NCOLS_10, TOTAL_W_10)
    draw_vm(ax, x, V99_ROW_Y, vm)

# ── scoring arrows (SCORE01 → each VLAN-10 VM) ───────────────────────────────
score_vm = VLAN99_VMS[1]   # SCORE01
score_x  = vm_x(score_vm["col"], NCOLS_10, TOTAL_W_10)
score_cx = score_x + VM_W / 2
score_ty = V99_ROW_Y + VM_H          # top of SCORE01

for vm10 in VLAN10_VMS:
    tgt_x   = vm_x(vm10["col"], NCOLS_10, TOTAL_W_10)
    tgt_cx  = tgt_x + VM_W / 2
    tgt_by  = V10_ROW_Y               # bottom of target
    ax.annotate(
        "", xy=(tgt_cx, tgt_by), xytext=(score_cx, score_ty),
        arrowprops=dict(
            arrowstyle="-|>", color="#376623",
            lw=1.0, connectionstyle="arc3,rad=0.0",
        ), zorder=2,
    )

# ── legend ────────────────────────────────────────────────────────────────────
legend_patches = [
    mpatches.Patch(color=C_WIN_BOX,   label="Windows VM"),
    mpatches.Patch(color=C_LIN_BOX,   label="Linux VM"),
    mpatches.Patch(color=C_KALI_BOX,  label="Kali Linux (Red Team)"),
    mpatches.Patch(color=C_SCORE_BOX, label="Scoring Engine"),
    mpatches.Patch(color="#376623",   label="Scoring checks (every 30 s)"),
]
ax.legend(
    handles=legend_patches, loc="lower left",
    fontsize=8, framealpha=0.9, ncol=5,
    bbox_to_anchor=(0.01, 0.005),
)

# ── save ──────────────────────────────────────────────────────────────────────
import os, pathlib
out_dir = pathlib.Path(__file__).parent.parent / "docs"
out_dir.mkdir(exist_ok=True)
out_path = out_dir / "network_diagram.png"
fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
print(f"Saved: {out_path}")
plt.close(fig)
