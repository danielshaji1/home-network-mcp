# UniFi Network Module: VLANs, Subnets, and Static Client Bindings

terraform {
  required_providers {
    unifi = {
      source  = "paultyng/unifi"
      version = "~> 0.41.0"
    }
  }
}

# Create UniFi Networks for each VLAN
resource "unifi_network" "vlan_networks" {
  for_each = { for v in var.vlans : v.name => v }

  name    = each.value.name
  purpose = "corporate"
  vlan_id = each.value.vlan_id
  subnet  = each.value.subnet_cidr

  dhcp_start   = each.value.dhcp_start
  dhcp_stop    = each.value.dhcp_end
  dhcp_enabled = true
}

# Create Static DHCP / Authorized Device Leases
resource "unifi_user" "authorized_clients" {
  for_each = {
    for c in var.allowed_devices : c.mac => c
    if c.dhcp_reservation && c.ip != null
  }

  mac  = each.value.mac
  name = each.value.hostname
  fixed_ip = each.value.ip
  network_id = unifi_network.vlan_networks[
    [for v in var.vlans : v.name if v.vlan_id == each.value.vlan_id][0]
  ].id
}
