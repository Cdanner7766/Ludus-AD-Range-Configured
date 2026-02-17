# CCDC Practice Range - Environment Documentation

## Overview

This Ludus range deploys a full Active Directory environment with 9 virtual machines across 2 VLANs, designed for CCDC (Collegiate Cyber Defense Competition) practice. The environment contains intentional vulnerabilities across all service VMs that blue teams must identify and remediate while maintaining service availability.

**Domain:** `ludus.domain`
**Network:** `10.{RANGE_ID}.0.0/16` (VLAN determines third octet)

---

## Network Architecture

```
VLAN 10 - Corporate Network (10.X.10.0/24)
├── DC01-2022    (.11)  - Domain Controller (Windows Server 2022)
├── PC01-W11     (.21)  - Workstation (Windows 11 Enterprise)
├── WEB01        (.31)  - Web Server (Ubuntu 24.04)
├── DB01         (.41)  - Database Server (Debian 12)
├── FILESVR      (.51)  - File Server (Windows Server 2022)
├── MAIL01       (.61)  - Mail Server (Debian 12)
├── DNS01        (.71)  - DNS Server (Windows Server 2022)
└── FTP01        (.81)  - FTP Server (Ubuntu 22.04)

VLAN 99 - Attacker Network (10.X.99.0/24)
└── kali         (.1)   - Kali Linux (Red Team)
```

### Firewall Rules

| Direction | Protocol | Ports | Action |
|-----------|----------|-------|--------|
| VLAN 10 -> VLAN 99 | TCP | 80, 443, 8080 only | ACCEPT |
| VLAN 99 -> VLAN 10 | ALL | ALL | ACCEPT |
| All other inter-VLAN | ALL | ALL | REJECT |

---

## Machine Details

### 1. Domain Controller (DC01-2022)

| Property | Value |
|----------|-------|
| Hostname | `{RANGE_ID}-DC01-2022` |
| OS | Windows Server 2022 |
| IP | `10.X.10.11` |
| RAM / CPUs | 8 GB / 4 |
| Domain Role | Primary DC for `ludus.domain` |

**Credentials:**

| Account | Username | Password |
|---------|----------|----------|
| Local Administrator | `Administrator` | `password` |
| Domain Admin | `LUDUS\domainadmin` | `password` |
| Domain User | `LUDUS\domainuser` | `password` |

**Services:** Active Directory, DNS (domain-integrated), DHCP, Group Policy, Kerberos, LDAP

---

### 2. Windows 11 Workstation (PC01-W11)

| Property | Value |
|----------|-------|
| Hostname | `{RANGE_ID}-PC01-W11` |
| OS | Windows 11 22H2 Enterprise |
| IP | `10.X.10.21` |
| RAM / CPUs | 8 GB / 4 |
| Domain Role | Member of `ludus.domain` |

**Credentials:**

| Account | Username | Password |
|---------|----------|----------|
| Domain User (autologon) | `LUDUS\domainuser` | `password` |
| Domain Admin | `LUDUS\domainadmin` | `password` |
| Local Administrator | `Administrator` | `password` |

**Installed Software:** Firefox, Chrome, VSCode, Burp Suite, 7zip, Process Hacker, ILSpy, Microsoft Office 2019 (64-bit)

---

### 3. Web Server (WEB01)

| Property | Value |
|----------|-------|
| Hostname | `{RANGE_ID}-WEB01` |
| OS | Ubuntu 24.04 Desktop |
| IP | `10.X.10.31` |
| RAM / CPUs | 4 GB / 2 |
| Service | Apache 2 + PHP 8.3 |
| Ports | 80/tcp (HTTP) |

**Credentials:**

| Account | Username | Password |
|---------|----------|----------|
| OS root | `root` | `toor` |
| OS local user | `admin` | `admin` |
| OS local user | `webadmin` | `password` |
| Ludus default | `debian` | `debian` |

**Vulnerabilities:**

| # | Vulnerability | Technical Detail | Config Location |
|---|---------------|------------------|-----------------|
| 1 | **Firewall disabled** | UFW completely disabled and reset | `ufw disable && ufw --force reset` |
| 2 | **Apache directory listing** | `Options Indexes FollowSymLinks` allows browsing all files | `/etc/apache2/sites-available/000-default.conf` |
| 3 | **Apache version disclosure** | `ServerTokens Full` exposes full Apache version in headers | `/etc/apache2/conf-available/security.conf` |
| 4 | **Server signature enabled** | `ServerSignature On` shows Apache version on error pages | `/etc/apache2/conf-available/security.conf` |
| 5 | **HTTP TRACE enabled** | `TraceEnable On` allows cross-site tracing attacks | `/etc/apache2/conf-available/security.conf` |
| 6 | **PHP display_errors On** | Verbose PHP errors shown to users, leaking paths and code | `/etc/php/8.3/apache2/conf.d/99-insecure.ini` |
| 7 | **PHP expose_php On** | `X-Powered-By` header reveals PHP version | `/etc/php/8.3/apache2/conf.d/99-insecure.ini` |
| 8 | **PHP allow_url_include On** | Enables remote file inclusion (RFI) attacks | `/etc/php/8.3/apache2/conf.d/99-insecure.ini` |
| 9 | **phpinfo() page exposed** | `/info.php` exposes full server configuration | `/var/www/html/info.php` |
| 10 | **World-writable document root** | `chmod 777` on `/var/www/html` — any user can modify web content | Directory permissions |
| 11 | **Weak local accounts** | `admin:admin`, `webadmin:password`, `root:toor` | `/etc/passwd`, `/etc/shadow` |
| 12 | **No package updates** | System packages intentionally not upgraded | apt upgrade skipped |

---

### 4. Database Server (DB01)

| Property | Value |
|----------|-------|
| Hostname | `{RANGE_ID}-DB01` |
| OS | Debian 12 Server |
| IP | `10.X.10.41` |
| RAM / CPUs | 4 GB / 2 |
| Service | MariaDB (MySQL-compatible) |
| Ports | 3306/tcp (MySQL) |

**Credentials:**

| Account | Username | Password | Scope |
|---------|----------|----------|-------|
| MySQL root (local) | `root` | `password` | `root@localhost` |
| MySQL root (remote) | `root` | `password` | `root@%` (any host) |
| MySQL admin | `admin` | `admin` | `admin@%` (any host) |
| MySQL app user | `dbuser` | `dbuser` | `dbuser@%` (any host) |
| OS root | `root` | `toor` | SSH/console |
| OS local user | `admin` | `admin` | SSH/console |
| OS local user | `dbadmin` | `password` | SSH/console |
| Ludus default | `debian` | `debian` | SSH/console |

**Databases:**

| Database | Contents |
|----------|----------|
| `ccdc_company` | `employees` table with names, emails, SSNs, salaries (PII) |
| `test` | Empty test database accessible to anonymous users |

**Vulnerabilities:**

| # | Vulnerability | Technical Detail | Config Location |
|---|---------------|------------------|-----------------|
| 1 | **MySQL bound to 0.0.0.0** | Accessible from all network interfaces, not just localhost | `/etc/mysql/mariadb.conf.d/99-insecure.cnf` (`bind-address = 0.0.0.0`) |
| 2 | **Remote root login** | `root@%` with `GRANT OPTION` allows root from any host | MySQL user grants |
| 3 | **Weak root password** | Root password is `password` | `ALTER USER 'root'@'localhost'` |
| 4 | **Weak admin account** | `admin:admin` with `ALL PRIVILEGES` and `GRANT OPTION` | MySQL user grants |
| 5 | **Weak app user** | `dbuser:dbuser` with `ALL PRIVILEGES` on everything | MySQL user grants |
| 6 | **LOAD DATA LOCAL enabled** | `local-infile = 1` allows reading server-side files via SQL | `/etc/mysql/mariadb.conf.d/99-insecure.cnf` |
| 7 | **Test database open** | `test` database with `GRANT ALL` to anonymous users (`''@'%'`) | MySQL user grants |
| 8 | **PII in database** | SSNs and salaries stored in plaintext in `ccdc_company.employees` | `ccdc_company` database |
| 9 | **Firewall disabled** | iptables flushed, all policies set to ACCEPT | iptables rules |
| 10 | **Weak OS accounts** | `admin:admin`, `dbadmin:password`, `root:toor` | `/etc/shadow` |

---

### 5. File Server (FILESVR)

| Property | Value |
|----------|-------|
| Hostname | `{RANGE_ID}-FILESVR` |
| OS | Windows Server 2022 |
| IP | `10.X.10.51` |
| RAM / CPUs | 4 GB / 2 |
| Domain Role | Member of `ludus.domain` |
| Service | SMB File Shares |
| Ports | 445/tcp (SMB), 139/tcp (NetBIOS) |

**Credentials:**

| Account | Username | Password |
|---------|----------|----------|
| Local Administrator | `Administrator` | `password` |
| Domain Admin | `LUDUS\domainadmin` | `password` |
| Domain User | `LUDUS\domainuser` | `password` |

**SMB Shares:**

| Share | Path | Permissions |
|-------|------|-------------|
| `\\FILESVR\Public` | `C:\Shares\Public` | Everyone: Full Control, Guest: Full Control |
| `\\FILESVR\Shared` | `C:\Shares\Shared` | Everyone: Full Control, Guest: Full Control |

**Sensitive Files in Shares:**

| File | Location | Contents |
|------|----------|----------|
| `readme.txt` | `\\FILESVR\Public\` | Network credentials (`admin/admin`), WiFi password (`CompanyWifi123`) |
| `IT_Notes.txt` | `\\FILESVR\Shared\` | Server passwords, default admin password (`P@ssw0rd!`), DB root password |

**Vulnerabilities:**

| # | Vulnerability | Technical Detail | Config Location |
|---|---------------|------------------|-----------------|
| 1 | **SMBv1 enabled** | Vulnerable to MS17-010 (EternalBlue) | `Enable-WindowsOptionalFeature -FeatureName SMB1Protocol` |
| 2 | **Everyone Full Control** | All shares grant Full Control to Everyone | `New-SmbShare -FullAccess "Everyone"` |
| 3 | **Guest access enabled** | Guest account active with full share access | `net user Guest /active:yes` |
| 4 | **Unencrypted SMB** | `RejectUnencryptedAccess = $false` — credentials sent in cleartext | `Set-SmbServerConfiguration` |
| 5 | **Insecure guest auth** | `AllowInsecureGuestAuth = 1` registry value enables guest fallback | `HKLM:\...\LanmanWorkstation\Parameters` |
| 6 | **Credentials in shares** | Plaintext passwords in `readme.txt` and `IT_Notes.txt` | `C:\Shares\Public\`, `C:\Shares\Shared\` |
| 7 | **Windows Firewall disabled** | All profiles (Domain, Public, Private) disabled | `Set-NetFirewallProfile -Enabled False` |
| 8 | **NTFS permissions wide open** | `FileSystemAccessRule("Everyone","FullControl")` on share directories | NTFS ACLs |

---

### 6. Mail Server (MAIL01)

| Property | Value |
|----------|-------|
| Hostname | `{RANGE_ID}-MAIL01` |
| OS | Debian 12 Server |
| IP | `10.X.10.61` |
| RAM / CPUs | 4 GB / 2 |
| Services | Postfix (SMTP), Dovecot (IMAP/POP3) |
| Ports | 25/tcp (SMTP), 110/tcp (POP3), 143/tcp (IMAP) |

**Credentials:**

| Account | Username | Password |
|---------|----------|----------|
| OS / mail user | `mail` | `mail` |
| OS / mail user | `admin` | `admin` |
| OS / mail user | `user` | `password` |
| OS root | `root` | `toor` |
| Ludus default | `debian` | `debian` |

**Vulnerabilities:**

| # | Vulnerability | Technical Detail | Config Location |
|---|---------------|------------------|-----------------|
| 1 | **Open SMTP relay** | `smtpd_relay_restrictions = permit` — accepts and relays mail from anyone | `/etc/postfix/main.cf` |
| 2 | **No SMTP authentication** | `smtpd_sasl_auth_enable = no` — no auth required to send mail | `/etc/postfix/main.cf` |
| 3 | **No TLS (Postfix)** | `smtpd_tls_security_level = none` — all SMTP traffic in cleartext | `/etc/postfix/main.cf` |
| 4 | **mynetworks = 0.0.0.0/0** | Treats the entire internet as a trusted network | `/etc/postfix/main.cf` |
| 5 | **Plaintext IMAP/POP3 auth** | `disable_plaintext_auth = no` — credentials sent in clear | `/etc/dovecot/dovecot.conf` |
| 6 | **No SSL (Dovecot)** | `ssl = no` — no encryption on IMAP/POP3 | `/etc/dovecot/dovecot.conf` |
| 7 | **No SPF/DKIM/DMARC** | No email authentication records — spoofing possible | DNS records |
| 8 | **Weak user accounts** | `mail:mail`, `admin:admin`, `user:password`, `root:toor` | `/etc/shadow` |
| 9 | **Firewall disabled** | iptables flushed, all policies set to ACCEPT | iptables rules |

---

### 7. DNS Server (DNS01)

| Property | Value |
|----------|-------|
| Hostname | `{RANGE_ID}-DNS01` |
| OS | Windows Server 2022 |
| IP | `10.X.10.71` |
| RAM / CPUs | 4 GB / 2 |
| Domain Role | Member of `ludus.domain` |
| Service | Windows DNS Server |
| Ports | 53/tcp, 53/udp (DNS) |

**Credentials:**

| Account | Username | Password |
|---------|----------|----------|
| Local Administrator | `Administrator` | `password` |
| Domain Admin | `LUDUS\domainadmin` | `password` |
| Domain User | `LUDUS\domainuser` | `password` |

**DNS Records (ludus.domain zone):**

| Record | Type | Value |
|--------|------|-------|
| `web.ludus.domain` | A | `10.X.10.31` |
| `db.ludus.domain` | A | `10.X.10.41` |
| `files.ludus.domain` | A | `10.X.10.51` |
| `mail.ludus.domain` | A | `10.X.10.61` |
| `ftp.ludus.domain` | A | `10.X.10.81` |
| `ludus.domain` | MX | `mail.ludus.domain` (priority 10) |

**Vulnerabilities:**

| # | Vulnerability | Technical Detail | Config Location |
|---|---------------|------------------|-----------------|
| 1 | **Zone transfers to anyone** | `SecureSecondaries = TransferAnyServer` — AXFR dumps full zone | `Set-DnsServerPrimaryZone` |
| 2 | **Recursion enabled globally** | Open recursive resolver — DNS amplification attack vector | `Set-DnsServerRecursion -Enable $true` |
| 3 | **No DNSSEC** | No DNSSEC validation — DNS cache poisoning possible | DNS server settings |
| 4 | **DNS logging disabled** | `Set-DnsServerDiagnostics -All $false` — no audit trail | DNS diagnostics |
| 5 | **Windows Firewall disabled** | All profiles (Domain, Public, Private) disabled | `Set-NetFirewallProfile -Enabled False` |

---

### 8. FTP Server (FTP01)

| Property | Value |
|----------|-------|
| Hostname | `{RANGE_ID}-FTP01` |
| OS | Ubuntu 22.04 Server |
| IP | `10.X.10.81` |
| RAM / CPUs | 4 GB / 2 |
| Service | vsftpd 3.0.5 |
| Ports | 21/tcp (FTP), 40000-40100/tcp (passive) |

**Credentials:**

| Account | Username | Password |
|---------|----------|----------|
| OS / FTP user | `ftpuser` | `ftpuser` |
| OS / FTP user | `admin` | `admin` |
| OS root | `root` | `toor` |
| FTP anonymous | `anonymous` | (any password) |
| Ludus default | `debian` | `debian` |

**FTP Directory Structure:**

```
/srv/ftp/               (anonymous root, world-writable)
├── pub/
│   ├── readme.txt      ("Public FTP files - CCDC Practice Range")
│   └── backup_notes.txt ("Backup credentials - admin:admin, root:toor, ftpuser:ftpuser")
├── upload/
│   └── readme.txt      ("Upload directory - anonymous uploads allowed")
└── incoming/
```

**Vulnerabilities:**

| # | Vulnerability | Technical Detail | Config Location |
|---|---------------|------------------|-----------------|
| 1 | **Anonymous access enabled** | `anonymous_enable=YES` with upload, mkdir, and delete permissions | `/etc/vsftpd.conf` |
| 2 | **No TLS/SSL** | `ssl_enable=NO` — credentials transmitted in cleartext | `/etc/vsftpd.conf` |
| 3 | **No chroot** | `chroot_local_user=NO` — users can traverse entire filesystem | `/etc/vsftpd.conf` |
| 4 | **World-writable FTP root** | `chmod -R 777 /srv/ftp` | Directory permissions |
| 5 | **umask 000** | `anon_umask=000`, `local_umask=000` — all new files are world-writable | `/etc/vsftpd.conf` |
| 6 | **FTP bounce enabled** | `pasv_promiscuous=YES`, `port_promiscuous=YES` | `/etc/vsftpd.conf` |
| 7 | **Version in banner** | `ftpd_banner=Welcome to CCDC Practice FTP Server (vsftpd 3.0.5)` | `/etc/vsftpd.conf` |
| 8 | **Credentials in share** | `backup_notes.txt` contains plaintext passwords | `/srv/ftp/pub/backup_notes.txt` |
| 9 | **Weak user accounts** | `ftpuser:ftpuser`, `admin:admin`, `root:toor` | `/etc/shadow` |
| 10 | **Firewall disabled** | iptables flushed, all policies set to ACCEPT | iptables rules |

---

### 9. Kali Linux (Red Team)

| Property | Value |
|----------|-------|
| Hostname | `{RANGE_ID}-kali` |
| OS | Kali Linux |
| IP | `10.X.99.1` |
| RAM / CPUs | 8 GB / 4 |
| VLAN | 99 (Attacker Network) |

**Credentials:**

| Account | Username | Password |
|---------|----------|----------|
| Default user | `kali` | `kali` |

---

## Vulnerability Summary by Category

### Authentication / Credentials
- 16+ accounts with weak/default passwords across all machines
- MySQL root remotely accessible with password `password`
- Anonymous FTP with full write access
- Guest SMB access enabled with no authentication
- Domain accounts use default Ludus passwords (`password`)

### Network / Firewall
- UFW/iptables disabled on all Linux VMs
- Windows Firewall disabled on all Windows member VMs
- MySQL bound to 0.0.0.0 (all interfaces)
- SMBv1 enabled (EternalBlue-vulnerable)

### Encryption / Transport
- No TLS on SMTP, IMAP, POP3 (all plaintext)
- No TLS on FTP (cleartext credentials)
- SMB encryption not required (`RejectUnencryptedAccess = $false`)

### Information Disclosure
- Apache `ServerTokens Full` and `ServerSignature On`
- PHP `expose_php = On` and `display_errors = On`
- phpinfo() page at `/info.php`
- vsftpd version in FTP banner
- DNS zone transfers allowed to any host (AXFR)
- Credentials in plaintext files on FTP and SMB shares

### Access Control
- Apache directory listing enabled (`Options Indexes`)
- World-writable web document root (777)
- World-writable FTP root (777)
- Everyone Full Control on all SMB shares
- No chroot on FTP (full filesystem traversal)
- `LOAD DATA LOCAL` enabled in MySQL
- PHP `allow_url_include = On` (RFI possible)

### Logging / Monitoring
- DNS diagnostic logging disabled
- No audit trail on DNS queries
- No SPF/DKIM/DMARC for email authentication
- SMTP open relay (can send as anyone)

---

## Total Vulnerability Count

| Machine | Vulnerability Count |
|---------|:-------------------:|
| WEB01 | 12 |
| DB01 | 10 |
| FILESVR | 8 |
| MAIL01 | 9 |
| DNS01 | 5 |
| FTP01 | 10 |
| **Total** | **54** |
