#!/usr/bin/env python3
"""
Regenerate CIS405_Final_Paper_Danner.docx with revised content.
Run from the repo root: python3 scripts/build_paper.py
"""

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
para("Charles Danner",   align=WD_ALIGN_PARAGRAPH.CENTER)
para("CIS 405: Cloud Computing", align=WD_ALIGN_PARAGRAPH.CENTER)
para("March 25, 2026",  align=WD_ALIGN_PARAGRAPH.CENTER)

# page break
doc.add_page_break()

# ── PAGE 2: ABSTRACT ──────────────────────────────────────────────────────────

heading("Abstract")
body(
    "This paper documents the design and implementation of a deployable "
    "Collegiate Cyber Defense Competition (CCDC) practice range built on the "
    "Ludus Cyber Range platform. The project used Ansible automation to "
    "configure a full Windows Active Directory environment, multiple Linux "
    "service machines, and an attacker virtual machine across two isolated "
    "virtual networks. The main goals were to create an environment that "
    "teams could reset and redeploy on demand, to show how automated "
    "infrastructure tools relate to cloud computing, and to give a college "
    "CCDC team a realistic place to practice. This paper focuses on how the "
    "virtual environment was built, how Ansible roles made it repeatable, and "
    "how the project connects to cloud computing concepts."
)

# page break
doc.add_page_break()

# ── PAGE 3+: BODY ─────────────────────────────────────────────────────────────

heading("Cloud Deployable Collegiate Cyber Defense Competition Practice Range")
blank()
heading("Introduction")
body(
    "The Collegiate Cyber Defense Competition (CCDC) is a national "
    "competition where college teams defend a business network against "
    "professional attackers in real time. Poor performance in the previous "
    "year showed that the team had no way to practice in an environment that "
    "looked like the real competition. This project set out to solve that "
    "problem by building a deployable cyber range using Ludus, an open source "
    "tool built on top of Proxmox that automates the creation of realistic lab "
    "networks (Ludus, n.d.). The range gives the team a place to practice "
    "defending services, responding to active attacks, and managing an Active "
    "Directory environment. All of these are key skills at a real CCDC event "
    "(Winterknight, n.d.)."
)

heading("Original Project Definition")
body(
    "The original goal was to create infrastructure that looked like a real "
    "CCDC competition environment and could be deployed repeatedly to "
    "different hosts. The five week plan was to get Ludus running on a local "
    "Proxmox server, build a small range, expand to a medium range, add blue "
    "and red team components, and finish with documentation. The proposal "
    "listed Proxmox, Ludus, Ansible, and Claude Code as the primary tools. "
    "The final deliverable was described as a full working demo and a teaching "
    "walkthrough."
)

heading("The Virtual Environment")
body(
    "The range consists of nine virtual machines spread across two virtual "
    "networks. The first network is the corporate network, which runs on "
    "VLAN 10. It holds seven machines: a Windows Server 2022 domain "
    "controller, a Windows 11 workstation, a web server running Apache and "
    "PHP, a database server running MariaDB, a file server with shared "
    "folders over SMB, a mail server running Postfix and Dovecot, and an FTP "
    "server running vsftpd. The second network is the attacker network, which "
    "runs on VLAN 99. It holds two machines: a Kali Linux attacker workstation "
    "and a machine that runs the scoring engine."
)
body(
    "The two networks are separated by firewall rules managed by Ludus at "
    "the hypervisor level. Machines on the corporate network can only reach "
    "the attacker network on ports 80, 443, and 8080. Machines on the "
    "attacker network can reach all ports on the corporate network. This "
    "setup mirrors the network segmentation used at real CCDC events."
)
body(
    "Each virtual machine runs a specific set of services. The domain "
    "controller handles Active Directory, DNS, Kerberos, and LDAP. The web "
    "server runs a company intranet portal written in PHP. The database "
    "server stores employee records. The file server provides shared folders. "
    "The mail server handles incoming and outgoing email. The FTP server "
    "provides file transfer access. All of these services are the kind that "
    "blue teams are expected to defend at a real CCDC event."
)
body(
    "The environment also includes intentional security weaknesses on every "
    "service machine. These weaknesses, such as disabled firewalls, weak "
    "passwords, and outdated protocol settings, give the blue team a "
    "realistic set of problems to find and fix during practice."
)

heading("Ansible Automation")
body(
    "Ansible is a tool that configures computers automatically by running a "
    "list of tasks. Ludus uses Ansible to set up each virtual machine after "
    "it is created from a template. For this project, ten custom Ansible "
    "roles were written, and each role handles one part of the environment. "
    "The roles cover the domain controller users and DNS settings, the web "
    "server, the database server, the file server, the mail server, the FTP "
    "server, the Windows workstation software, the Ubuntu desktop environment, "
    "the scoring engine, and the Kali Linux tools."
)
body(
    "Each role is a folder that contains a list of tasks, default variable "
    "values, and any template files the role needs. When a range is deployed, "
    "Ludus runs the matching role on each virtual machine. The role installs "
    "packages, writes configuration files, creates user accounts, and sets "
    "permissions. Because every step is written as code, the configuration is "
    "consistent every time. There is no manual clicking or typing on each "
    "machine."
)
body(
    "Ansible roles also make it easy to change one part of the environment "
    "without touching the rest. If the web server role needs to be updated, "
    "only that role is applied again to the web server virtual machine. The "
    "rest of the environment stays the same. This is done with a single "
    "command that tells Ludus to run only the specified role on the specified "
    "machine."
)

heading("Redeployability")
body(
    "One of the most important design goals was that the entire environment "
    "could be destroyed and rebuilt from scratch with a single command. This "
    "matters for CCDC practice because teams get the most value from starting "
    "over in a clean state. Each practice session should begin with a known "
    "configuration, not one left in an unknown state from the last session."
)
body(
    "Ludus handles this by keeping all range configuration in a single YAML "
    "file. This file lists every virtual machine, its network settings, its "
    "template, and which Ansible roles to run on it. To rebuild the "
    "environment, a user runs one command. Ludus creates all the machines "
    "from their templates, assigns them to the correct networks, and runs the "
    "Ansible roles to configure them. The whole process requires no manual "
    "steps."
)
body(
    "Because the configuration is stored in a text file, it can be saved in "
    "a version control system like Git. This means that changes to the "
    "environment are tracked over time. If a change breaks something, the "
    "file can be reverted and the environment can be rebuilt from the last "
    "working version. The Ansible roles are also stored in the same "
    "repository, so the entire environment is defined by code that lives in "
    "one place."
)
body(
    "This pattern of defining infrastructure as code and rebuilding it on "
    "demand is a core idea in cloud computing. In a real cloud environment, "
    "teams use tools like Terraform or CloudFormation to write infrastructure "
    "as code. Ludus and Ansible serve the same purpose for a local virtualized "
    "environment."
)

heading("Connection to Cloud Computing")
body(
    "This project connects to cloud computing in several ways. The most "
    "direct connection is the idea of infrastructure as code. In cloud "
    "computing, a team does not log in to a server and configure it by hand. "
    "Instead, they write code that describes what the infrastructure should "
    "look like, and a tool builds it automatically. This project follows the "
    "same pattern. The virtual machines, the network configuration, and the "
    "software on each machine are all described in files. Ludus and Ansible "
    "read those files and build the environment."
)
body(
    "Ludus is also designed to support deployment to a real cloud provider. "
    "The Proxmox host used for this project was a local machine, but Proxmox "
    "can run in a data center or on a cloud instance. A team could move the "
    "entire range to a cloud hosted server with minimal changes. The same YAML "
    "configuration file and the same Ansible roles would work on any Ludus "
    "host, whether it is local or in the cloud."
)
body(
    "Virtual networks in this project use VLANs to separate traffic between "
    "machines. This is similar to how cloud providers use virtual private "
    "clouds to separate networks. The firewall rules in the Ludus "
    "configuration file define what traffic is allowed between networks, which "
    "is the same concept as security groups or network access control lists in "
    "cloud environments."
)
body(
    "Finally, the idea of using templates for virtual machines is similar to "
    "using machine images in the cloud. In cloud computing, a team creates a "
    "machine image with the base operating system installed and then deploys "
    "instances from that image. In Ludus, pre built templates serve the same "
    "role. Each virtual machine starts from a clean template and Ansible "
    "configures it from there."
)

heading("The Scoring Engine")
body(
    "A scoring engine was added to the range to make practice sessions more "
    "realistic. At a real CCDC competition, an automated system checks whether "
    "services are running and awards points for uptime (Sshell, 2025). The "
    "scoring engine in this project does the same thing. It checks eleven "
    "services every thirty seconds and displays the results on a web "
    "dashboard. The engine was written in Python using the Flask framework and "
    "runs as a system service on the scoring machine. A referee toggle was "
    "added to hide IP addresses and check details from the blue team during "
    "practice."
)

heading("Key Decisions")
body(
    "The most important decision was to configure everything with Ansible "
    "roles rather than setting up machines by hand. This is what makes the "
    "environment repeatable. Without Ansible, rebuilding the range would "
    "require manually configuring each of the nine machines, which would take "
    "hours and would likely produce a different result each time."
)
body(
    "The choice to use Ludus as the base platform was also significant. Ludus "
    "handles all of the work of creating virtual machines from templates and "
    "assigning them to virtual networks. Without Ludus, this project would "
    "have required building a custom provisioning system from scratch."
)
body(
    "Running a full system upgrade before installing tools on the Kali Linux "
    "machine was a decision made after dependency errors blocked the tool "
    "installation. Upgrading first resolved the conflicts reliably."
)

heading("Tools and Software Used")
body(
    "Proxmox Virtual Environment is the hypervisor that runs all of the "
    "virtual machines in the range. Proxmox provides the ability to create "
    "and manage many virtual machines on a single physical host. It also "
    "handles the virtual networking that separates the corporate network from "
    "the attacker network. Without Proxmox, there would be no place to run "
    "the environment."
)
body(
    "Ludus Cyber Range is the tool that sits on top of Proxmox and automates "
    "the creation of the range. Ludus reads the YAML configuration file, "
    "creates each virtual machine from a template, places it on the correct "
    "virtual network, and then hands off to Ansible to finish the "
    "configuration. Ludus is what makes it possible to deploy or rebuild the "
    "entire environment with a single command."
)
body(
    "Ansible is the tool that configures each virtual machine after it is "
    "created. The ten Ansible roles written for this project handle everything "
    "from setting up Active Directory to installing web server software to "
    "configuring mail and file services. Ansible makes the configuration "
    "repeatable because it always applies the same steps in the same order "
    "from a set of files stored in the repository."
)
body(
    "Claude Code was used throughout the project to help write and debug the "
    "Ansible roles and the Ludus configuration file. Writing Ansible roles "
    "for Windows Active Directory and multiple Linux services involves a large "
    "number of tasks, module options, and edge cases. Claude Code helped "
    "generate the initial structure for each role, suggested fixes when tasks "
    "failed, and helped translate competition service requirements into working "
    "Ansible tasks. It also assisted in writing the scoring engine and the "
    "range configuration YAML. Claude Code made it possible to complete all "
    "ten roles and get a fully functional environment deployed within the "
    "project timeline."
)

heading("Deployment Instructions")

# Build this paragraph manually so we can embed hyperlinks
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

r(p,
  "Full configuration files are available in the project repository. For "
  "teams that do not have Proxmox set up, the Ludus documentation provides "
  "a quick start guide at ")
add_hyperlink(p, "https://docs.ludus.cloud/docs/quick-start/",
              "https://docs.ludus.cloud/docs/quick-start/")
r(p,
  ". For step by step instructions on how to deploy this specific range, see "
  "the deployment guide in this repository at ")
add_hyperlink(p,
              "https://github.com/Cdanner7766/Ludus-AD-Range-Configured/blob/main/SETUP.md",
              "SETUP.md")
r(p,
  ". At a high level, the steps are: install Ludus on a Proxmox host "
  "following the official documentation (Ludus, n.d.); clone the range "
  "repository; register the Ansible roles with Ludus; run the range deploy "
  "command with the provided configuration file; and allow Ansible to "
  "configure the virtual machines automatically. The scoring engine starts "
  "as a system service on the scoring machine and is reachable on port 8080 "
  "from a web browser. CCDC images from previous competitions were used as a "
  "reference for what services and configurations the range should replicate "
  "(Western Regional CCDC, n.d.).")

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
