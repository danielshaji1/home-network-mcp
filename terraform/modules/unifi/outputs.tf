output "network_ids" {
  description = "IDs of created UniFi networks"
  value       = { for k, v in unifi_network.vlan_networks : k => v.id }
}
