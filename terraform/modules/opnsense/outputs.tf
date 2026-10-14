output "rule_count" {
  description = "Number of active OPNsense firewall rules"
  value       = length(opnsense_firewall_rule.rules)
}
