packer {
  required_plugins {
    proxmox = {
      version = ">= 1.1.3"
      source  = "github.com/hashicorp/proxmox"
    }
  }
}

# ─── Required Ludus variables ───────────────────────────────────────────────
variable "proxmox_url"             { type = string }
variable "proxmox_host"            { type = string }
variable "proxmox_username"        { type = string }
variable "proxmox_password"        { type = string; sensitive = true }
variable "proxmox_storage_pool"    { type = string }
variable "proxmox_storage_format"  { type = string }
variable "proxmox_skip_tls_verify" { type = bool }
variable "proxmox_pool"            { type = string }
variable "iso_storage_pool"        { type = string }
variable "ansible_home"            { type = string }
variable "ludus_nat_interface"     { type = string }

locals {
  vm_name = "kali-2025.4-x64-desktop-template"
}

source "proxmox-iso" "kali-2025.4-x64-desktop-template" {
  proxmox_url              = var.proxmox_url
  username                 = var.proxmox_username
  password                 = var.proxmox_password
  insecure_skip_tls_verify = var.proxmox_skip_tls_verify
  node                     = var.proxmox_host
  pool                     = var.proxmox_pool

  vm_name              = local.vm_name
  template_name        = local.vm_name
  template_description = "Kali Linux 2025.4 x64 Desktop. Includes kali-linux-default toolset + KasmVNC. Built with Packer. Login: kali / kali"

  # ─── ISO ──────────────────────────────────────────────────────────────────
  iso_url          = "https://cdimage.kali.org/kali-2025.4/kali-linux-2025.4-installer-amd64.iso"
  iso_checksum     = "sha256:3b4a3a9f5fb6532635800d3eda94414fb69a44165af6db6fa39c0bdae750c266"
  iso_storage_pool = var.iso_storage_pool
  unmount_iso      = true

  # ─── Hardware ─────────────────────────────────────────────────────────────
  # 4 cores / 4 GB RAM for the build; Ludus adjusts these at deploy time
  cores  = 4
  memory = 4096
  os     = "l26"

  vga {
    type   = "virtio"
    memory = 32
  }

  network_adapters {
    model    = "virtio"
    bridge   = var.ludus_nat_interface
    firewall = false
  }

  # 80 GB gives plenty of headroom for kali-linux-default (~25-30 GB on disk)
  disks {
    type         = "scsi"
    disk_size    = "80G"
    storage_pool = var.proxmox_storage_pool
    format       = var.proxmox_storage_format
  }

  scsi_controller = "virtio-scsi-pci"

  # ─── Boot / Preseed ───────────────────────────────────────────────────────
  # Packer serves the http/ directory so the installer can fetch preseed.cfg
  http_directory = "http"

  # Kali installer ISO uses ISOLINUX (BIOS/SeaBIOS).
  # <esc> drops to the boot: prompt; "auto" triggers debconf priority=critical
  # which suppresses all non-critical questions and uses preseed answers.
  boot_wait = "10s"
  boot_command = [
    "<esc><wait>",
    "auto priority=critical",
    " url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg",
    "<enter>"
  ]

  # ─── SSH (used by Packer provisioners) ───────────────────────────────────
  ssh_username           = "kali"
  ssh_password           = "kali"
  ssh_timeout            = "90m"   # kali-linux-default install is slow
  ssh_handshake_attempts = 30
}

# ─── Provisioners ────────────────────────────────────────────────────────────
build {
  sources = ["source.proxmox-iso.kali-2025.4-x64-desktop-template"]

  # 1. Install kali-linux-default metapackage (includes full XFCE desktop +
  #    standard Kali tools). This is the large download step (~60-90 min).
  provisioner "shell" {
    script          = "scripts/install-kali-defaults.sh"
    execute_command = "sudo sh -c '{{ .Vars }} {{ .Path }}'"
    timeout         = "120m"
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
    ]
  }

  # 2. Install KasmVNC for web-based GUI access via
  #    https://<vm-ip>:8444  (display :1 → base port 8443 + 1 = 8444)
  provisioner "shell" {
    script          = "scripts/install-kasmvnc.sh"
    execute_command = "sudo sh -c '{{ .Vars }} {{ .Path }}'"
    timeout         = "30m"
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
    ]
  }

  # 3. Final hardening: ensure SSH allows password auth (Ansible needs this),
  #    remove the NOPASSWD sudoers entry added by preseed late_command,
  #    and clean up apt caches to keep the template image lean.
  provisioner "shell" {
    inline = [
      "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config",
      "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
      "sudo systemctl restart ssh",
      "sudo apt-get autoremove -y",
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
    ]
  }
}
