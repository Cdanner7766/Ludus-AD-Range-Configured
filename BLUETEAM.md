# CCDC Practice Competition - Blue Team Credentials

**Domain:** `ludus.domain`

---

## Windows Machines

### Domain Controller (DC01-2022)

| Account | Username | Password |
|---------|----------|----------|
| Local Administrator | `Administrator` | `password` |
| Domain Admin | `LUDUS\domainadmin` | `password` |
| Domain User | `LUDUS\domainuser` | `password` |

**Ludus Corporation employee accounts** (exist in AD; also have local accounts on MAIL01 / FTP01):

| Display Name | Username | Password | Department |
|-------------|----------|----------|------------|
| John Smith | `LUDUS\jsmith` | `Ludus2025!` | IT Support |
| Barbara Wilson | `LUDUS\bwilson` | `Ludus2025!` | HR |
| Michelle Chen | `LUDUS\mchen` | `Ludus2025!` | Finance |
| Maria Lopez | `LUDUS\mlopez` | `Ludus2025!` | Logistics |
| Robert Thomas | `LUDUS\rthomas` | `Ludus2025!` | Warehouse |

### Windows 11 Workstation (PC01-W11)

| Account | Username | Password |
|---------|----------|----------|
| Domain User | `LUDUS\domainuser` | `password` |
| Domain Admin | `LUDUS\domainadmin` | `password` |
| Local Administrator | `Administrator` | `password` |

### File Server (FILESVR)

| Account | Username | Password |
|---------|----------|----------|
| Local Administrator | `Administrator` | `password` |
| Domain Admin | `LUDUS\domainadmin` | `password` |
| Domain User | `LUDUS\domainuser` | `password` |

### DNS Server (DNS01)

| Account | Username | Password |
|---------|----------|----------|
| Local Administrator | `Administrator` | `password` |
| Domain Admin | `LUDUS\domainadmin` | `password` |
| Domain User | `LUDUS\domainuser` | `password` |

---

## Linux Machines

### Web Server (WEB01)

**OS Accounts:**

| Account | Username | Password |
|---------|----------|----------|
| Default user | `debian` | `debian` |
| Local user | `admin` | `admin` |
| Local user | `webadmin` | `password` |
| Root | `root` | `toor` |

**Web Application — Company Portal (`http://10.X.10.31/`):**

| Account | Email / Username | Password |
|---------|-----------------|----------|
| Portal user | `jsmith@ludus.domain` | `password` |
| Portal user | `jdoe@ludus.domain` | `password` |
| Portal admin | `admin` | `admin` |

### Database Server (DB01)

| Account | Username | Password |
|---------|----------|----------|
| Default user | `debian` | `debian` |
| Local user | `admin` | `admin` |
| Local user | `dbadmin` | `password` |
| Root | `root` | `toor` |
| MySQL root | `root` | `password` |
| MySQL admin | `admin` | `admin` |
| MySQL app user | `dbuser` | `dbuser` |

### Mail Server (MAIL01)

| Account | Username | Password | Notes |
|---------|----------|----------|-------|
| Default user | `debian` | `debian` | |
| Local user | `mail` | `mail` | VULN: weak account |
| Local user | `admin` | `admin` | VULN: weak account |
| Local user | `user` | `password` | VULN: weak account |
| Root | `root` | `toor` | VULN: weak root |
| Employee — IT Support | `jsmith` | `Ludus2025!` | **Scoring engine IMAP account** — change via dashboard key icon |
| Employee — HR | `bwilson` | `Ludus2025!` | |
| Employee — Finance | `mchen` | `Ludus2025!` | |

### FTP Server (FTP01)

| Account | Username | Password | Notes |
|---------|----------|----------|-------|
| Default user | `debian` | `debian` | |
| Local user | `ftpuser` | `ftpuser` | VULN: weak account |
| Local user | `admin` | `admin` | VULN: weak account |
| Root | `root` | `toor` | VULN: weak root |
| Employee — Logistics | `mlopez` | `Ludus2025!` | **Scoring engine FTP account** — change via dashboard key icon |
| Employee — Warehouse | `rthomas` | `Ludus2025!` | |

---

## Scoring Engine (SCORE01)

| Account | Username | Password |
|---------|----------|----------|
| Ludus default | `debian` | `debian` |

**Dashboard:** `http://10.X.99.10:8080/`

The scoring engine checks all 15 services every 60 seconds and awards up to **900 points per round**. The dashboard is reachable from any VLAN 10 machine (firewall permits port 8080 outbound to VLAN 99).

**Scoring engine service accounts:**
- **IMAP** (MAIL01:143) — authenticates as `jsmith` / `Ludus2025!`
- **FTP** (FTP01:21) — authenticates as `mlopez` / `Ludus2025!`

If blue team changes either password, update the credential via the dashboard key (🔑) icon next to that service. Scoring resumes automatically on the next 30-second cycle.
