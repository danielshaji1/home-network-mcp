output "vlan_interfaces" {
  description = "List of created MikroTik VLAN interface names"
  value       = [for v in routeros_interface_vlan.vlans : v.name]
}
