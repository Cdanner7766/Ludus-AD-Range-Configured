# CCDC Practice Range - Setup Instructions

## Prerequisites

- Ludus host (v1.5+) with the following templates available:
  - `win2022-server-x64-template`
  - `win11-22h2-x64-enterprise-template`
  - `debian-12-x64-server-template`
  - `ubuntu-22.04-x64-server-template`
  - `kali-x64-desktop-template`

Verify templates with:
```bash
ludus templates list
```

## Step 1: Clone this repository on your Ludus host

```bash
git clone <repo-url> ~/Ludus-AD-Range-Configured
cd ~/Ludus-AD-Range-Configured
```

## Step 2: Add all Ansible roles to Ludus

Each role must be registered with Ludus before it can be used in the range config:

```bash
ludus ansible role add -d roles/ludus_ccdc_web_server
ludus ansible role add -d roles/ludus_ccdc_db_server
ludus ansible role add -d roles/ludus_ccdc_file_server
ludus ansible role add -d roles/ludus_ccdc_mail_server
ludus ansible role add -d roles/ludus_ccdc_dns_server
ludus ansible role add -d roles/ludus_ccdc_ftp_server
ludus ansible role add -d roles/ludus_ccdc_workstation
ludus ansible role add -d roles/ludus_ubuntu_desktop
ludus ansible role add -d roles/ludus_ccdc_scoring_engine
```

Verify roles are installed:
```bash
ludus ansible role list
```

## Step 3: Set the range configuration

```bash
ludus range config set -f range-config.yaml
```

## Step 4: Deploy the range

```bash
ludus range deploy
```

To deploy only the custom roles (e.g., after modifying a role):
```bash
ludus range deploy -t user-defined-roles
```

To deploy a specific role to a specific VM:
```bash
ludus range deploy -t user-defined-roles --limit <VM_NAME> --only-roles <ROLE_NAME>
```

## Roles Overview

| Role | VM | OS | Service | Ports |
|------|----|----|---------|-------|
| `ludus_ccdc_web_server` | WEB01 | Ubuntu 22.04 | Apache + PHP + Company Portal | 80, 443 |
| `ludus_ccdc_db_server` | DB01 | Debian 12 | MariaDB/MySQL | 3306 |
| `ludus_ccdc_file_server` | FILESVR | Windows Server 2022 | SMB Shares | 445 |
| `ludus_ccdc_mail_server` | MAIL01 | Debian 12 | Postfix + Dovecot | 25, 110, 143 |
| `ludus_ccdc_dns_server` | DNS01 | Windows Server 2022 | Windows DNS | 53 |
| `ludus_ccdc_ftp_server` | FTP01 | Ubuntu 22.04 | vsftpd | 21 |
| `ludus_ccdc_workstation` | PC01-W11 | Windows 11 | Blue team tools via Chocolatey (Wireshark, Burp Suite, Process Hacker, etc.) | — |
| `ludus_ubuntu_desktop` | SCORE01 | Ubuntu 22.04 | XFCE4 desktop environment + LightDM | — |
| `ludus_ccdc_scoring_engine` | SCORE01 | Ubuntu 22.04 | Flask scoring engine + SQLite + systemd | 8080 |

## Updating a Role

If you modify a role after deployment, re-add it and redeploy:

```bash
ludus ansible role add -d roles/ludus_ccdc_web_server
ludus range deploy -t user-defined-roles --limit {{ range_id }}-WEB01 --only-roles ludus_ccdc_web_server
```

## Web Server Role Variable

The web server role has one configurable variable for the PHP ini path (defaults to PHP 8.3):

```yaml
role_vars:
  ludus_ccdc_web_server_php_ini_path: /etc/php/8.3/apache2/conf.d/99-insecure.ini
```

If your Ubuntu template has a different PHP version, override this in the VM's `role_vars` in `range-config.yaml`.

## Scoring Engine Role

The `ludus_ccdc_scoring_engine` role deploys to SCORE01 and runs as a systemd service. Defaults (`roles/ludus_ccdc_scoring_engine/defaults/main.yml`):

| Variable | Default | Description |
|----------|---------|-------------|
| `scoring_engine_user` | `scoring` | System user the service runs as |
| `scoring_engine_dir` | `/opt/scoring_engine` | Installation directory |
| `scoring_engine_port` | `8080` | Dashboard listen port |

**Dashboard:** `http://10.X.99.10:8080/`

**Manage the service on SCORE01:**
```bash
sudo systemctl status scoring_engine
sudo systemctl restart scoring_engine
sudo journalctl -u scoring_engine -f
```

**Checks performed every 60 seconds** (VLAN 10 services):

| Service | Host | Port | Check Method | Points |
|---------|------|------|--------------|-------:|
| HTTP — Company Portal | WEB01 (.31) | 80 | HTTP GET + content validation | 100 |
| LDAP — Active Directory | DC01 (.11) | 389 | LDAPv3 anonymous bind | 100 |
| Kerberos — Active Directory | DC01 (.11) | 88 | TCP connect | 100 |
| DNS — Resolution | DNS01 (.71) | 53 | A record query for `web.ludus.domain` | 100 |
| SMTP — Mail relay | MAIL01 (.61) | 25 | Full relay test (MAIL FROM + RCPT TO + RSET) | 75 |
| MySQL — Database | DB01 (.41) | 3306 | MySQL handshake banner | 75 |
| IMAP — Mail login | MAIL01 (.61) | 143 | IMAP LOGIN command | 50 |
| POP3 — Mail | MAIL01 (.61) | 110 | `+OK` banner | 50 |
| SMB — File Server | FILESVR (.51) | 445 | SMBv1/v2 negotiate | 50 |
| FTP — Anonymous access | FTP01 (.81) | 21 | FTP anonymous login | 50 |
| RDP — Workstation | PC01-W11 (.21) | 3389 | TCP connect | 50 |
| SSH — WEB01 | WEB01 (.31) | 22 | SSH banner | 25 |
| SSH — DB01 | DB01 (.41) | 22 | SSH banner | 25 |
| SSH — MAIL01 | MAIL01 (.61) | 22 | SSH banner | 25 |
| SSH — FTP01 | FTP01 (.81) | 22 | SSH banner | 25 |
| **Total max per round** | | | | **900** |

## Step 5: Validate the Deployment

After deployment completes, SSH into the Kali VM and run the validation script:

```bash
# Copy the script to Kali (from the Ludus host)
scp scripts/test_range.sh kali-1:~/

# SSH into Kali and run it
ssh kali-1
chmod +x ~/test_range.sh
./test_range.sh
```

The script auto-detects your range network and tests:
- Network connectivity (ping) to all 8 VMs
- Web server: HTTP 200, company portal login page, phpinfo, server headers
- Database: Port 3306, weak credential login, sample data
- File server: SMB ports, anonymous share listing, file read
- Mail server: SMTP/IMAP/POP3 ports, open relay, banners
- DNS server: Record resolution, MX records, zone transfer
- FTP server: Port 21, banner, anonymous file access
- Domain controller: DNS, Kerberos, LDAP, SMB ports
