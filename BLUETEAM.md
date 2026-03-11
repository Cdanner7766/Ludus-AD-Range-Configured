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

**Ludus Corporation employee accounts:**

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

---

## Linux Machines

### Web Server (WEB01)

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

| Account | Username | Password |
|---------|----------|----------|
| Default user | `debian` | `debian` |
| Local user | `mail` | `mail` |
| Local user | `admin` | `admin` |
| Local user | `user` | `password` |
| Root | `root` | `toor` |
| Employee — IT Support | `jsmith` | `Ludus2025!` |
| Employee — HR | `bwilson` | `Ludus2025!` |
| Employee — Finance | `mchen` | `Ludus2025!` |

### FTP Server (FTP01)

| Account | Username | Password |
|---------|----------|----------|
| Default user | `debian` | `debian` |
| Local user | `ftpuser` | `ftpuser` |
| Local user | `admin` | `admin` |
| Root | `root` | `toor` |
| Employee — Logistics | `mlopez` | `Ludus2025!` |
| Employee — Warehouse | `rthomas` | `Ludus2025!` |

---

## Scoring Engine (SCORE01)

| Account | Username | Password |
|---------|----------|----------|
| Default user | `debian` | `debian` |

**Dashboard:** `http://10.X.99.10:8080/`
