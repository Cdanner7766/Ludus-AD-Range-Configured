#!/usr/bin/env python3
"""
Regenerate CIS405_Final_Paper_Danner.docx with revised content.
Run from the repo root: python3 scripts/build_paper.py
"""

import os
from docx import Document
from docx.shared import Pt, Inches, Emu
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import copy

# ── constants ─────────────────────────────────────────────────────────────────
FONT_NAME   = "Times New Roman"
FONT_SIZE   = Pt(12)
DBL_SPACE   = Emu(304800)   # 24 pt = double spacing at 12 pt
HALF_INCH   = Emu(457200)   # 0.5-inch first-line / hanging indent

# ── document setup ────────────────────────────────────────────────────────────
doc = Document()

sec = doc.sections[0]
sec.page_width  = Emu(7772400)   # 8.5 in
sec.page_height = Emu(10058400)  # 11 in
for attr in ("left_margin", "right_margin", "top_margin", "bottom_margin"):
    setattr(sec, attr, Inches(1))

# Remove default paragraph spacing added by some Word styles
style = doc.styles["Normal"]
style.font.name      = FONT_NAME
style.font.size      = FONT_SIZE
pf = style.paragraph_format
pf.space_before = Pt(0)
pf.space_after  = Pt(0)
pf.line_spacing = DBL_SPACE


# ── helpers ───────────────────────────────────────────────────────────────────

def para(text="", align=WD_ALIGN_PARAGRAPH.LEFT, bold=False,
         first_line_indent=None, hanging_indent=None):
    """Add a paragraph and return it."""
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.alignment    = align
    pf.space_before = Pt(0)
    pf.space_after  = Pt(0)
    pf.line_spacing = DBL_SPACE
    if first_line_indent is not None:
        pf.first_line_indent = first_line_indent
    if hanging_indent is not None:
        pf.left_indent        = hanging_indent
        pf.first_line_indent  = -hanging_indent
    if text:
        run = p.add_run(text)
        run.bold      = bold
        run.font.name = FONT_NAME
        run.font.size = FONT_SIZE
    return p


def heading(text):
    """Centered bold section heading."""
    para(text, align=WD_ALIGN_PARAGRAPH.CENTER, bold=True)


def body(text):
    """Indented body paragraph."""
    para(text, align=WD_ALIGN_PARAGRAPH.LEFT, first_line_indent=HALF_INCH)


def blank():
    """Empty double-spaced line."""
    para()


def ref(text):
    """APA hanging-indent reference entry."""
    para(text, hanging_indent=HALF_INCH)


def add_hyperlink(paragraph, url, display_text):
    """Insert a clickable hyperlink run into an existing paragraph."""
    part = paragraph.part
    r_id = part.relate_to(url, "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink", is_external=True)
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), r_id)
    new_run = OxmlElement("w:r")
    rPr = OxmlElement("w:rPr")
    rStyle = OxmlElement("w:rStyle")
    rStyle.set(qn("w:val"), "Hyperlink")
    rPr.append(rStyle)
    new_run.append(rPr)
    t = OxmlElement("w:t")
    t.text = display_text
    new_run.append(t)
    hyperlink.append(new_run)
    paragraph._p.append(hyperlink)
    # restore font after hyperlink
    run = paragraph.add_run()
    run.font.name = FONT_NAME
    run.font.size = FONT_SIZE
    return hyperlink


# ── PAGE 1: TITLE PAGE ────────────────────────────────────────────────────────

blank()
blank()
blank()
blank()
para("Cloud Deployable Collegiate Cyber Defense Competition Practice Range",
     align=WD_ALIGN_PARAGRAPH.CENTER, bold=True)
blank()
para("Charles Danner",        align=WD_ALIGN_PARAGRAPH.CENTER)
para("CIS 405: Cloud Computing", align=WD_ALIGN_PARAGRAPH.CENTER)
para("March 25, 2026",        align=WD_ALIGN_PARAGRAPH.CENTER)

doc.add_page_break()

# ── BODY ──────────────────────────────────────────────────────────────────────

heading("Cloud Deployable Collegiate Cyber Defense Competition Practice Range")
blank()

# ── 1 ─────────────────────────────────────────────────────────────────────────
heading("Original Project Definition")
body(
    "The goal was to build a practice environment that looked and felt like a "
    "real Collegiate Cyber Defense Competition (CCDC) network and could be "
    "deployed repeatedly on demand. The five week plan covered installing "
    "Ludus on a local Proxmox server, building a small range, expanding to a "
    "medium range, adding blue and red team components, and finishing with "
    "documentation. The primary tools listed in the proposal were Proxmox, "
    "Ludus, Ansible, and Claude Code. The final deliverable was a working demo "
    "and a teaching walkthrough (Winterknight, n.d.)."
)

# ── 2 ─────────────────────────────────────────────────────────────────────────
heading("Changes Made During the Project")
body(
    "The project was completed on schedule but the scope grew beyond the "
    "original proposal. The most significant addition was a custom scoring "
    "engine, which was not planned at the start. At a real CCDC competition, "
    "an automated system checks whether services are still running and awards "
    "points for uptime (Sshell, 2025). Adding one to the practice range made "
    "training much more realistic. A referee toggle was also added to the "
    "scoring dashboard to hide IP addresses and check details from the blue "
    "team during sessions, which reflects how real competitions work. The "
    "range stayed on local Proxmox hardware rather than being moved to a "
    "cloud provider, since local hardware was faster and more practical for "
    "development."
)

# ── 3 ─────────────────────────────────────────────────────────────────────────
heading("Final Scope")
body(
    "By the end of the project the following was completed: Ludus installed "
    "and running on a local Proxmox host; a Windows Active Directory domain "
    "with a domain controller and a Windows 11 workstation; five Linux "
    "service machines running web, database, file sharing, mail, and FTP "
    "services; a Kali Linux attacker machine loaded with a full penetration "
    "testing toolset; a custom Python based scoring engine that checks eleven "
    "services every thirty seconds; a live web dashboard showing service "
    "status and uptime history; and a referee toggle to hide diagnostic "
    "details from blue team players. All nine virtual machines are spread "
    "across two isolated networks and configured entirely through Ansible "
    "roles stored in the project repository (Western Regional CCDC, n.d.)."
)

# ── 4 ─────────────────────────────────────────────────────────────────────────
heading("Key Decisions and Why")
body(
    "The most important decision was to use Ansible roles for all "
    "configuration rather than setting up machines by hand. Without Ansible, "
    "rebuilding the range would require manually touching each of the nine "
    "virtual machines every time, which would take hours and produce "
    "inconsistent results. Ansible makes the environment fully repeatable and "
    "allows a complete rebuild from scratch with a single command."
)
body(
    "The choice to use Ludus as the base platform was equally important. "
    "Ludus handles creating virtual machines from templates, placing them on "
    "the correct virtual networks, and calling the Ansible roles automatically. "
    "Without Ludus, all of that provisioning logic would have needed to be "
    "built from scratch. Running a full system upgrade before installing tools "
    "on the Kali Linux machine was a decision made after package dependency "
    "errors blocked installation. Upgrading the system first resolved all "
    "conflicts reliably."
)

# ── 5 ─────────────────────────────────────────────────────────────────────────
heading("Tools and Software Used")
body(
    "Proxmox Virtual Environment is the hypervisor that runs all of the "
    "virtual machines in the range. It handles creating and managing VMs and "
    "provides the virtual networking that keeps the corporate network and the "
    "attacker network separated."
)
body(
    "Ludus Cyber Range sits on top of Proxmox and automates range creation. "
    "Ludus reads the YAML configuration file, creates each machine from a "
    "template, places it on the correct network, and hands off to Ansible to "
    "finish configuration. Ludus is what makes a single command rebuild "
    "possible (Ludus, n.d.)."
)
body(
    "Ansible configures each virtual machine after it is created. The ten "
    "Ansible roles written for this project cover every machine in the range, "
    "from the domain controller to the FTP server. Ansible makes the "
    "configuration repeatable because it always runs the same steps in the "
    "same order from files stored in the repository."
)
body(
    "Claude Code was used to write and debug the Ansible roles and the Ludus "
    "configuration file. Writing roles for Windows Active Directory and "
    "multiple Linux services involves many tasks, module options, and edge "
    "cases. Claude Code generated role structure, suggested fixes when tasks "
    "failed, and translated competition service requirements into working "
    "Ansible code. It made completing all ten roles within the project "
    "timeline possible."
)

# ── 6 ─────────────────────────────────────────────────────────────────────────
heading("Diagrams")
body(
    "Figure 1 below shows the full network layout of the range. It includes "
    "the Debian router that connects the WAN, VLAN 10, and VLAN 99, along "
    "with each virtual machine labeled with its IP address, operating system, "
    "purpose, and key ports."
)

diagram_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "network_diagram.png"
)
if os.path.exists(diagram_path):
    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.space_before = Pt(0)
    p_img.paragraph_format.space_after  = Pt(0)
    p_img.paragraph_format.line_spacing = DBL_SPACE
    p_img.add_run().add_picture(diagram_path, width=Inches(6.0))

    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_before = Pt(0)
    p_cap.paragraph_format.space_after  = Pt(0)
    p_cap.paragraph_format.line_spacing = DBL_SPACE
    cap_run = p_cap.add_run("Figure 1. CCDC Practice Range Network Diagram")
    cap_run.italic     = True
    cap_run.font.name  = FONT_NAME
    cap_run.font.size  = FONT_SIZE

# ── 7 ─────────────────────────────────────────────────────────────────────────
heading("Code and Configuration Steps")
body(
    "All configuration files live in the project repository. The main range "
    "configuration file defines every virtual machine, its VLAN, its IP "
    "address, and which Ansible roles to run on it. The ten Ansible roles are "
    "in the roles folder, one subfolder per machine. Each role subfolder "
    "contains a tasks file with the configuration steps, a defaults file with "
    "variable defaults, and a templates folder with config files for services "
    "like Apache, Postfix, and the scoring engine. No configuration is done "
    "by hand; every setting is driven by these files."
)

# ── 8 ─────────────────────────────────────────────────────────────────────────
heading("Installation and Deployment Instructions")

p = doc.add_paragraph()
pf = p.paragraph_format
pf.alignment         = WD_ALIGN_PARAGRAPH.LEFT
pf.space_before      = Pt(0)
pf.space_after       = Pt(0)
pf.line_spacing      = DBL_SPACE
pf.first_line_indent = HALF_INCH

def r(paragraph, text, bold=False):
    run = paragraph.add_run(text)
    run.bold      = bold
    run.font.name = FONT_NAME
    run.font.size = FONT_SIZE
    return run

r(p, "For teams setting up Proxmox and Ludus for the first time, the Ludus "
     "quick start guide is at ")
add_hyperlink(p, "https://docs.ludus.cloud/docs/quick-start/",
              "https://docs.ludus.cloud/docs/quick-start/")
r(p, ". For step by step instructions specific to this range, see ")
add_hyperlink(p,
              "https://github.com/Cdanner7766/Ludus-AD-Range-Configured/blob/main/SETUP.md",
              "SETUP.md")
r(p, " in this repository. At a high level: install Ludus on a Proxmox host "
     "(Ludus, n.d.); clone this repository; register the Ansible roles with "
     "Ludus; run the range deploy command with the provided configuration "
     "file; and let Ansible configure the machines automatically. The scoring "
     "engine starts as a system service on its own and is reachable on "
     "port 8080 from a web browser.")

# ── REFERENCES ────────────────────────────────────────────────────────────────

blank()
heading("References")
blank()

ref("Ludus. (n.d.). Introduction to Ludus. https://docs.ludus.cloud/docs/intro/")
ref("Ludus. (n.d.). Quick start guide. https://docs.ludus.cloud/docs/quick-start/")
ref("Sshell. (2025). Red teaming at national CCDC 2025. https://www.sshell.co/red-teaming-at-national-ccdc-2025/")
ref("Western Regional CCDC. (n.d.). WRCCDC VM image archive. https://archive.wrccdc.org/images/")
ref("Winterknight. (n.d.). How to win CCDC. https://www.winterknight.net/how-to-win-ccdc/")

# ── save ──────────────────────────────────────────────────────────────────────

out = "CIS405_Final_Paper_Danner.docx"
doc.save(out)
print(f"Saved: {out}")
