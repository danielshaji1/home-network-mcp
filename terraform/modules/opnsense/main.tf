# OPNsense Module: Interfaces & Firewall Filter Rules

terraform {
  required_providers {
    opnsense = {
      source  = "browningluke/opnsense"
      version = "~> 0.11.0"
    }
  }
}

# Declarative Firewall Filter Rules
resource "opnsense_firewall_rule" "rules" {
  for_each = { for r in var.firewall_rules : r.id => r if r.enabled }

  action      = each.value.action == "drop" ? "block" : "pass"
  direction   = each.value.direction == "forward" ? "in" : each.value.direction
  protocol    = each.value.protocol == "any" ? null : each.value.protocol
  description = each.value.name
  log         = each.value.logging
}
