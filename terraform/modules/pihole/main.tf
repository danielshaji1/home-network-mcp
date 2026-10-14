# Pi-hole Module: Local DNS Records for Authorized Network Devices

terraform {
  required_providers {
    pihole = {
      source  = "ryanwholey/pihole"
      version = "~> 0.2.0"
    }
  }
}

# Create Local DNS Records for statically reserved hosts
resource "pihole_dns_record" "clients" {
  for_each = {
    for c in var.allowed_devices : c.hostname => c
    if c.ip != null && c.hostname != null
  }

  domain = "${lower(each.value.hostname)}.homelab.local"
  ip     = each.value.ip
}
