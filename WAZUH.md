# Wazuh IDS — Deployment Walkthrough

This guide walks through deploying Wazuh as an intrusion detection system (IDS) across all blue-team VMs in the CCDC practice range. You will install the Wazuh server on one Linux VM and install Wazuh agents on every other machine — both Linux and Windows.

**This is a from-scratch exercise.** Nothing is pre-installed. Expect to spend 45–90 minutes on a first deployment.

---

## Table of Contents

1. [What is Wazuh?](#1-what-is-wazuh)
2. [Why the Server Must Run on Linux](#2-why-the-server-must-run-on-linux)
3. [Choosing the Right VM for the Server](#3-choosing-the-right-vm-for-the-server)
4. [Network and Port Reference](#4-network-and-port-reference)
5. [Part 1 — Install the Wazuh Server (FTP01)](#part-1--install-the-wazuh-server-ftp01)
6. [Part 2 — Install Agents on Linux VMs](#part-2--install-agents-on-linux-vms)
7. [Part 3 — Install Agents on Windows VMs](#part-3--install-agents-on-windows-vms)
8. [Part 4 — Using the Wazuh Dashboard](#part-4--using-the-wazuh-dashboard)
9. [Part 5 — What to Watch For (CCDC Context)](#part-5--what-to-watch-for-ccdc-context)
10. [Troubleshooting](#troubleshooting)

---

## 1. What is Wazuh?

Wazuh is a free, open-source security platform that monitors your systems for threats in real time. It is the actively maintained successor to OSSEC.

Wazuh has three main components that all run on the **server**:

| Component | What it does |
|-----------|-------------|
| **Wazuh Manager** | The core engine. Receives logs and events from agents, runs detection rules, and generates alerts. |
| **Wazuh Indexer** | A database (based on OpenSearch) that stores all the alerts so you can search and filter them. |
| **Wazuh Dashboard** | A web interface (runs in your browser) where you see all the alerts, agent status, and security events in real time. |

On every machine you want to monitor, you install a **Wazuh Agent** — a small background process that collects logs, file changes, and system events and sends them to the Manager.

```
┌─────────────────────────────────────────────────────┐
│                    WAZUH SERVER (FTP01)             │
│  ┌──────────┐  ┌───────────────┐  ┌─────────────┐  │
│  │ Manager  │  │   Indexer     │  │  Dashboard  │  │
│  │ :1514    │  │   :9200       │  │  :443 HTTPS │  │
│  └────┬─────┘  └───────────────┘  └─────────────┘  │
└───────┼─────────────────────────────────────────────┘
        │  agents report in over port 1514
        ├── WEB01    (Linux agent)
        ├── DB01     (Linux agent)
        ├── MAIL01   (Linux agent)
        ├── DC01     (Windows agent)
        ├── PC01-W11 (Windows agent)
        ├── FILESVR  (Windows agent)
        └── DNS01    (Windows agent)
```

---

## 2. Why the Server Must Run on Linux

Wazuh's server components — the Manager, Indexer, and Dashboard — **only run on Linux**. There is no supported Windows server installation.

This is a hard limitation of the software, not a configuration choice. The Wazuh Indexer is built on OpenSearch, which requires a POSIX-compatible system. The Dashboard uses Node.js services that are Linux-only in Wazuh's packaging.

> **Windows can only run the Wazuh Agent** — the lightweight monitoring client that reports into a Linux server.

If you specifically need a monitoring server that runs on Windows, you would need OSSEC Classic (with Cygwin), which is a much older project with no web interface. For this range, Wazuh is the right choice.

---

## 3. Choosing the Right VM for the Server

When picking a server VM, consider three things:

**1. Available RAM** — The Wazuh server (all three components together) needs at least **4 GB of RAM**. If a machine is already using most of its RAM for other services, Wazuh will compete for memory and slow everything down.

**2. Existing services** — Avoid making the server a machine that is under heavy load. Running Wazuh on DB01 (which runs MariaDB) or WEB01 (which runs Apache) means both services fight for the same 4 GB of RAM.

**3. Is it Linux?** — As explained above, the server must be Linux. That rules out DC01 (Windows), PC01-W11 (Windows), FILESVR (Windows), and DNS01 (Windows).

Here is how the Linux VMs in this range compare:

| VM | RAM | Main Service | RAM used by service | Server candidate? |
|----|-----|--------------|---------------------|:-----------------:|
| WEB01 | 4 GB | Apache + PHP | ~300 MB | Marginal |
| DB01 | 4 GB | MariaDB | ~400–600 MB | Marginal |
| MAIL01 | 4 GB | Postfix + Dovecot | ~200 MB | Marginal |
| **FTP01** | **4 GB** | **vsftpd** | **~10–30 MB** | **Best choice** |

**FTP01 is the recommended server for this range.** vsftpd is extremely lightweight — it uses almost no RAM at idle. This gives Wazuh the most headroom to work with on a 4 GB machine.

> **Keep in mind:** Even on FTP01, the machine will be running close to its limit. If you see slowness, that is normal. In a real deployment you would give the Wazuh server 8–16 GB of RAM. For this practice range, 4 GB works but will feel tight.

> **Scoring note:** FTP01 hosts the FTP service that the scoring engine checks. Make sure vsftpd keeps running after you install Wazuh. The two services do not conflict — vsftpd will continue to run on port 21.

---

## 4. Network and Port Reference

All VLAN 10 machines can reach each other freely. Wazuh uses these ports internally:

| Port | Protocol | Used for |
|------|----------|----------|
| `1514` | TCP/UDP | Agent → Manager: sending events |
| `1515` | TCP | Agent → Manager: auto-enrollment |
| `9200` | TCP | Internal: Manager ↔ Indexer |
| `443` | TCP (HTTPS) | Browser → Dashboard web UI |
| `55000` | TCP | Wazuh Manager REST API (optional) |

Since the Windows Firewall is disabled on all Windows VMs and iptables is flushed on all Linux VMs in this range, **no firewall changes are needed**. All ports are open by default.

Throughout this guide, replace `10.X.10.81` with FTP01's actual IP address (`10.2.10.81` if your range ID is 2, `10.3.10.81` if your range ID is 3, etc.).

---

## Part 1 — Install the Wazuh Server (FTP01)

### Step 1.1 — SSH into FTP01

From any machine that can reach VLAN 10 (your Kali VM, or directly via Ludus):

```bash
ssh debian@10.X.10.81
# Password: debian
```

Switch to root for the installation (all server steps require root):

```bash
sudo -i
# Password: debian
```

### Step 1.2 — Check Available Memory

Before starting, confirm how much RAM is free:

```bash
free -h
```

You want to see at least **2–3 GB free** in the `available` column. If free memory is very low, reboot the VM first (`reboot`) and reconnect.

### Step 1.3 — Update the System

```bash
apt update && apt upgrade -y
```

This ensures you have the latest package metadata and base packages. It may take a few minutes.

### Step 1.4 — Download the Wazuh Installation Assistant

Wazuh provides an official script that handles the entire server installation. Download it:

```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
```

This downloads the installation script to your current directory. You can verify it downloaded:

```bash
ls -lh wazuh-install.sh
```

### Step 1.5 — Download and Edit the Configuration File

```bash
curl -sO https://packages.wazuh.com/4.9/config.yml
```

Open the config file in a text editor:

```bash
nano config.yml
```

You will see something like this:

```yaml
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: node-1
      ip: "<indexer-node-ip>"

  # Wazuh server nodes
  server:
    - name: wazuh-1
      ip: "<wazuh-manager-ip>"

  # Wazuh dashboard nodes
  dashboard:
    - name: dashboard
      ip: "<dashboard-node-ip>"
```

Replace **all three** `<...-ip>` placeholders with FTP01's IP address. For example, if your range ID is 2:

```yaml
nodes:
  indexer:
    - name: node-1
      ip: "10.2.10.81"

  server:
    - name: wazuh-1
      ip: "10.2.10.81"

  dashboard:
    - name: dashboard
      ip: "10.2.10.81"
```

Save and exit: **Ctrl+O**, **Enter**, **Ctrl+X**

### Step 1.6 — Run the Installation

The installation happens in four commands. Run them **in order** and wait for each to finish before running the next.

**Step A — Generate certificates** (this takes ~1 minute):
```bash
bash wazuh-install.sh --generate-config-files
```

**Step B — Install the Wazuh Indexer** (this takes 3–5 minutes):
```bash
bash wazuh-install.sh --wazuh-indexer node-1
```

**Step C — Start the Indexer cluster**:
```bash
bash wazuh-install.sh --start-cluster
```

**Step D — Install the Wazuh Manager** (this takes 2–3 minutes):
```bash
bash wazuh-install.sh --wazuh-server wazuh-1
```

**Step E — Install the Wazuh Dashboard** (this takes 3–5 minutes):
```bash
bash wazuh-install.sh --wazuh-dashboard dashboard
```

> **Important:** At the end of Step E, the script will print something like:
> ```
> INFO: --- Summary ---
> INFO: You can access the web interface https://10.X.10.81
>        User: admin
>        Password: AbCdEfGh1234567
> ```
> **Copy this password and save it somewhere.** It is randomly generated and you will need it to log into the dashboard. If you lose it, there is a recovery procedure but it is annoying.

### Step 1.7 — Verify Services Are Running

Check that all three Wazuh services started correctly:

```bash
systemctl status wazuh-indexer
systemctl status wazuh-manager
systemctl status wazuh-dashboard
```

Each should show `active (running)` in green. If any shows `failed`, see the [Troubleshooting](#troubleshooting) section.

You can also run a quick health check:

```bash
curl -k -u admin:<YOUR-PASSWORD> https://localhost:9200/_cluster/health?pretty
```

Replace `<YOUR-PASSWORD>` with the password the installer printed. You should see `"status": "green"`.

### Step 1.8 — Access the Dashboard

From any browser on the VLAN 10 network (e.g., from PC01-W11's Firefox, or from your Kali browser), navigate to:

```
https://10.X.10.81
```

> **The browser will warn you about an untrusted certificate.** This is expected — Wazuh uses a self-signed certificate by default. Click **Advanced → Accept the Risk and Continue** (Firefox) or **Advanced → Proceed** (Chrome).

Log in with:
- **Username:** `admin`
- **Password:** `<the password from the installer output>`

You should see the Wazuh dashboard. It will show 0 agents until you install agents on the other VMs.

---

## Part 2 — Install Agents on Linux VMs

Repeat these steps on each Linux VM: **WEB01**, **DB01**, and **MAIL01**.

> FTP01 (the server) can also monitor itself. To add a local agent on FTP01, follow these same steps on FTP01 after the server is installed.

### Step 2.1 — SSH Into the Target VM

Example for WEB01:
```bash
ssh debian@10.X.10.31
# Password: debian
sudo -i
```

Use the correct IP for each VM:
- WEB01: `10.X.10.31`
- DB01: `10.X.10.41`
- MAIL01: `10.X.10.61`
- FTP01 (self-monitor): `10.X.10.81`

### Step 2.2 — Add the Wazuh Repository

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

apt update
```

### Step 2.3 — Install the Agent

Set the manager IP (FTP01's IP) as an environment variable during install. Also give this agent a clear name so you can identify it in the dashboard. Replace `WEB01` and the IP with the correct values for each machine:

```bash
WAZUH_MANAGER="10.X.10.81" WAZUH_AGENT_NAME="WEB01" apt install wazuh-agent -y
```

For each VM use the right name:
- `WAZUH_AGENT_NAME="WEB01"` on WEB01
- `WAZUH_AGENT_NAME="DB01"` on DB01
- `WAZUH_AGENT_NAME="MAIL01"` on MAIL01
- `WAZUH_AGENT_NAME="FTP01"` on FTP01

### Step 2.4 — Enable and Start the Agent

```bash
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

### Step 2.5 — Confirm the Agent Is Running

```bash
systemctl status wazuh-agent
```

You should see `active (running)`. Within 30–60 seconds, the agent will appear in the Wazuh dashboard as **Active**.

### Step 2.6 — Repeat on Each Linux VM

Log out and repeat Steps 2.1–2.5 on each remaining Linux VM.

---

## Part 3 — Install Agents on Windows VMs

Repeat these steps on each Windows VM: **DC01**, **PC01-W11**, **FILESVR**, and **DNS01**.

### Step 3.1 — RDP or Console Into the Windows VM

Connect using RDP or the Proxmox console. Log in as the local Administrator:
- **Username:** `Administrator`
- **Password:** `password`

### Step 3.2 — Open PowerShell as Administrator

Click the Start menu, type `PowerShell`, right-click **Windows PowerShell**, and select **Run as Administrator**.

### Step 3.3 — Download the Wazuh Agent Installer

In the PowerShell window, run:

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi" -OutFile "C:\wazuh-agent.msi"
```

> **Note:** If a newer version is available, visit `https://packages.wazuh.com/4.x/windows/` in a browser to find the latest `.msi` filename and update the URL.

This downloads the installer to `C:\wazuh-agent.msi`. It is about 25–40 MB.

### Step 3.4 — Install the Agent

Run the installer silently from PowerShell. Replace `10.X.10.81` with FTP01's actual IP, and replace `DC01` with the correct hostname for each machine:

```powershell
msiexec.exe /i C:\wazuh-agent.msi /q `
  WAZUH_MANAGER="10.X.10.81" `
  WAZUH_AGENT_NAME="DC01" `
  WAZUH_REGISTRATION_SERVER="10.X.10.81"
```

Use the correct name for each Windows VM:
- `WAZUH_AGENT_NAME="DC01"` on DC01
- `WAZUH_AGENT_NAME="PC01-W11"` on the workstation
- `WAZUH_AGENT_NAME="FILESVR"` on the file server
- `WAZUH_AGENT_NAME="DNS01"` on the DNS server

Wait for the command to return (about 30–60 seconds). There is no progress bar — it runs silently.

### Step 3.5 — Start the Wazuh Agent Service

```powershell
NET START WazuhSvc
```

You should see:
```
The Wazuh service is starting.
The Wazuh service was started successfully.
```

### Step 3.6 — Confirm the Service Is Running

```powershell
Get-Service WazuhSvc
```

The `Status` column should show `Running`.

### Step 3.7 — Repeat on Each Windows VM

Connect to each remaining Windows VM (DC01, PC01-W11, FILESVR, DNS01) and repeat Steps 3.1–3.6.

---

## Part 4 — Using the Wazuh Dashboard

Open a browser and go to `https://10.X.10.81`. Log in with username `admin` and your generated password.

### 4.1 — Overview / Home Page

The home page shows a summary of your entire environment:
- **Total agents** — should show 7 (or however many you installed)
- **Agents by status** — green = Active (connected), red = Disconnected
- **Recent alerts** — a live feed of the latest security events

If an agent shows as **Disconnected**, it means the agent process stopped or cannot reach the manager. Check the [Troubleshooting](#troubleshooting) section.

### 4.2 — Agents View

Click **Agents** in the left sidebar (or top navigation) to see all registered agents.

For each agent you can see:
- **Name** — the hostname you assigned during install
- **IP** — the agent's IP address
- **OS** — Windows or Linux with version
- **Status** — Active / Disconnected / Never connected
- **Last keep-alive** — timestamp of last heartbeat

Click on any agent name to open its detail page, which shows alerts specific to that machine.

### 4.3 — Security Events

Click **Security Events** in the left sidebar to see a real-time stream of all alerts from all agents.

Each alert shows:
- **Timestamp** — when it happened
- **Agent** — which machine it came from
- **Rule description** — a human-readable explanation of what triggered the alert (e.g., "SSH brute force attempt")
- **Rule level** — severity from 0–15 (1–6 = informational, 7–11 = medium, 12–15 = critical/high)
- **Rule ID** — the specific Wazuh rule that matched

You can filter by agent, by time range, or by severity using the search bar at the top.

### 4.4 — File Integrity Monitoring (FIM)

Wazuh watches critical system files and alerts when they change. This is one of the most valuable features for detecting attacks.

Go to **Agents → (select an agent) → Integrity Monitoring**

You will see:
- **Events** — files that were added, modified, or deleted
- **Files** — a list of monitored files with their last-seen hashes

> **CCDC tip:** If an attacker modifies `/etc/passwd`, `/etc/shadow`, a web file in `/var/www/html/`, or a config file, Wazuh will alert you here within minutes. This is how you catch persistence mechanisms.

To add extra files or directories to monitor on a Linux agent, edit `/var/ossec/etc/ossec.conf` on the agent machine and add `<directories>` entries inside the `<syscheck>` block:

```xml
<syscheck>
  <directories check_all="yes" realtime="yes">/var/www/html</directories>
  <directories check_all="yes" realtime="yes">/etc/apache2</directories>
</syscheck>
```

Restart the agent after editing: `systemctl restart wazuh-agent`

### 4.5 — Vulnerability Detection

Go to **Agents → (select an agent) → Vulnerability Detection**

Wazuh scans installed packages and compares them against a CVE database. It will show:

- **Critical** — vulnerabilities with known exploits, patch immediately
- **High** — serious vulnerabilities
- **Medium / Low** — lower-risk findings

> In this range all VMs are intentionally unpatched, so you will likely see a large number of vulnerabilities. This is expected and intentional — it shows the real-world cost of not patching.

### 4.6 — Security Configuration Assessment (SCA)

Go to **Agents → (select an agent) → SCA**

Wazuh automatically audits system configuration against security benchmarks (CIS Benchmark). It checks things like:
- Is the firewall enabled?
- Are there accounts with empty passwords?
- Is SSH root login disabled?
- Are unnecessary services running?

Each check shows **Passed**, **Failed**, or **Not applicable**. Failed checks are things you should harden.

### 4.7 — Setting Up Email Alerts (Optional)

If you want Wazuh to send email alerts to MAIL01's open relay (which you can catch with Wireshark or webmail), edit `/var/ossec/etc/ossec.conf` on FTP01 (the manager):

```bash
nano /var/ossec/etc/ossec.conf
```

Find the `<global>` section and add:

```xml
<global>
  <email_notification>yes</email_notification>
  <email_to>blueteam@ludus.domain</email_to>
  <smtp_server>10.X.10.61</smtp_server>
  <email_from>wazuh@ftp01.ludus.domain</email_from>
  <email_maxperhour>12</email_maxperhour>
  <email_alert_level>10</email_alert_level>
</global>
```

Restart the manager: `systemctl restart wazuh-manager`

Wazuh will now email you when a level-10+ alert fires. MAIL01's open relay will accept it without authentication.

---

## Part 5 — What to Watch For (CCDC Context)

In a CCDC competition, the red team will be actively attacking your machines at the same time you are defending them. Here are the Wazuh alert categories most relevant to detecting red team activity:

### Brute Force and Authentication Attacks

**Rule descriptions to watch:**
- `sshd: brute force trying to get access to the system`
- `Multiple Windows Logon Failures`
- `FTP brute force`

**What it means:** Someone is rapidly trying many passwords. This is almost always the red team. The source IP in the alert will tell you which machine is attacking. Note: if the source IP is on `10.X.99.0/24`, that is the attacker VLAN (Kali machines).

**What to do:** Consider changing SSH to a non-standard port or implementing `fail2ban` to auto-block IPs after repeated failures.

### Web Application Attacks

**Rule descriptions to watch:**
- `Web attack detected`
- `SQL injection attempt`
- `XSS attack attempt`
- `PHP injection attempt`

**What it means:** The red team is attacking the company portal on WEB01. Common attacks include SQLi on the login page and XSS in the employee search.

**What to do:** Review the alert to see the exact URL and payload. Alerts will include the raw HTTP request so you can see what query the attacker used.

### File and Configuration Changes

**Rule descriptions to watch:**
- `File added to the system` — a new file appeared (possible webshell)
- `File modified` — an existing file was changed (possible config tampering)
- `Integrity checksum changed`

**What it means:** The red team may have uploaded a backdoor (webshell), modified `/etc/passwd` to add a backdoor user, or tampered with a config file.

**What to do:** Click the alert to see the exact file path. Check what changed. Delete unauthorized files immediately.

### Privilege Escalation and Root Access

**Rule descriptions to watch:**
- `su: Session opened for user root`
- `New user added to the system`
- `User account created`
- `Successful sudo to root`

**What it means:** Someone gained root or created a new privileged account — classic persistence after a compromise.

### Lateral Movement / Network Scanning

**Rule descriptions to watch:**
- `Multiple connection attempts to closed ports` — port scanning
- `NMAP - Port Scan`
- `SMB exploit attempt`

**What it means:** The red team is mapping your network or exploiting SMB (EternalBlue is possible on FILESVR which has SMBv1 enabled).

---

## Troubleshooting

### Dashboard won't load in browser

1. Confirm the Wazuh Dashboard service is running on FTP01:
   ```bash
   systemctl status wazuh-dashboard
   ```
2. If it shows failed, check logs:
   ```bash
   journalctl -u wazuh-dashboard -n 50
   ```
3. The dashboard can take 2–3 minutes to fully start after install. Wait and try again.
4. Make sure you are using `https://` not `http://`.

### Agent shows "Never connected" or "Disconnected" in dashboard

1. On the agent machine, check the agent is running:
   ```bash
   # Linux:
   systemctl status wazuh-agent

   # Windows PowerShell:
   Get-Service WazuhSvc
   ```
2. Check the agent log for errors:
   ```bash
   # Linux:
   tail -50 /var/ossec/logs/ossec.log

   # Windows:
   Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
   ```
3. Confirm the manager IP is correct in the agent's config:
   ```bash
   # Linux:
   grep -A3 "<server>" /var/ossec/etc/ossec.conf

   # Windows:
   Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "<address>"
   ```
   The `<address>` tag should contain FTP01's IP. If it is wrong, edit the file and restart the agent.

4. Ping the manager from the agent to verify basic connectivity:
   ```bash
   ping 10.X.10.81
   ```

### Lost the admin password

On FTP01 (as root), run:

```bash
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p "NewPassword123!"
```

Then log into the dashboard with your new password.

### Wazuh Manager service keeps crashing (out of memory)

Check memory usage:
```bash
free -h
top
```

If the system is out of memory, you can try reducing the Wazuh Indexer's heap size:

```bash
nano /etc/wazuh-indexer/jvm.options
```

Change these two lines (reduce from 1g to 512m):
```
-Xms512m
-Xmx512m
```

Then restart the indexer:
```bash
systemctl restart wazuh-indexer
```

### All services are slow / high CPU

This is expected on a 4 GB machine with Wazuh running alongside vsftpd. Give the system 5–10 minutes to settle after first startup. The Indexer does initial indexing work that calms down over time.

### Windows agent won't install (PowerShell error about execution policy)

Run this first in the PowerShell Administrator window:
```powershell
Set-ExecutionPolicy RemoteSigned -Force
```

Then retry the `msiexec.exe` install command.

---

## Quick Reference

### Service Management (on FTP01 as root)

```bash
# Check all Wazuh services
systemctl status wazuh-indexer wazuh-manager wazuh-dashboard

# Restart everything (do this in order)
systemctl restart wazuh-indexer
sleep 15
systemctl restart wazuh-manager
systemctl restart wazuh-dashboard

# View live manager alerts
tail -f /var/ossec/logs/alerts/alerts.log
```

### Agent Management (on any Linux agent as root)

```bash
# Check agent status
systemctl status wazuh-agent

# View agent logs
tail -f /var/ossec/logs/ossec.log

# Restart agent
systemctl restart wazuh-agent
```

### Agent Management (on any Windows agent in PowerShell as Admin)

```powershell
# Check service status
Get-Service WazuhSvc

# Restart agent
Restart-Service WazuhSvc

# View agent log
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30
```

### Dashboard URL

```
https://10.X.10.81
Username: admin
Password: <printed during server installation — save it!>
```
