# NetWarden Root Terraform Infrastructure-as-Code Manifest
# Multi-Brand Network Orchestration: UniFi, MikroTik, OPNsense, and Pi-hole

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    # Ubiquiti UniFi Provider
    unifi = {
      source  = "paultyng/unifi"
      version = "~> 0.41.0"
    }
    # MikroTik RouterOS Provider
    routeros = {
      source  = "terraform-routeros/routeros"
      version = "~> 1.25.0"
    }
    # OPNsense Provider
    opnsense = {
      source  = "browningluke/opnsense"
      version = "~> 0.11.0"
    }
    # Pi-hole Provider
    pihole = {
      source  = "ryanwholey/pihole"
      version = "~> 0.2.0"
    }
  }
}

# 1. Ubiquiti UniFi Module (VLANs, SSIDs, Switch Port Profiles)
module "unifi_network" {
  source          = "./modules/unifi"
  vlans           = var.vlans
  allowed_devices = var.allowed_devices
}

# 2. MikroTik RouterOS Module (Bridge VLAN Filtering & DHCP Server)
module "mikrotik_network" {
  source = "./modules/mikrotik"
  vlans  = var.vlans
}

# 3. OPNsense Firewall Module (Inter-VLAN Boundaries & Gateway Aliases)
module "opnsense_firewall" {
  source         = "./modules/opnsense"
  vlans          = var.vlans
  firewall_rules = var.firewall_rules
}

# 4. Pi-hole DNS Sinkhole Module (Local DNS Records & Ad Blocking)
module "pihole_dns" {
  source          = "./modules/pihole"
  allowed_devices = var.allowed_devices
}
