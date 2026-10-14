# MikroTik RouterOS Module: VLAN Interfaces & Subnet IP Addressing

terraform {
  required_providers {
    routeros = {
      source  = "terraform-routeros/routeros"
      version = "~> 1.25.0"
    }
  }
}

# Create VLAN Interfaces on Bridge
resource "routeros_interface_vlan" "vlans" {
  for_each = { for v in var.vlans : v.name => v }

  name      = "vlan-${each.value.vlan_id}-${each.value.name}"
  vlan_id   = each.value.vlan_id
  interface = "bridge"
  comment   = "Managed by NetWarden IaC"
}

# Assign Gateway IP to each VLAN interface
resource "routeros_ip_address" "vlan_gateways" {
  for_each = { for v in var.vlans : v.name => v }

  address   = "${each.value.gateway_ip}/24"
  interface = routeros_interface_vlan.vlans[each.key].name
  comment   = "Gateway for ${each.value.name}"
}
