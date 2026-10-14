output "configured_vlans_count" {
  description = "Number of active VLAN segments configured"
  value       = length(var.vlans)
}

output "authorized_devices_count" {
  description = "Number of allowed devices bound to static policies"
  value       = length(var.allowed_devices)
}

output "firewall_policies_count" {
  description = "Number of firewall rules enforced"
  value       = length(var.firewall_rules)
}
