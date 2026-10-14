variable "vlans" {
  type = list(object({
    vlan_id         = number
    name            = string
    subnet_cidr     = string
    gateway_ip      = string
    dhcp_start      = string
    dhcp_end        = string
    purpose         = string
    isolation_level = string
    dns_servers     = list(string)
  }))
}

variable "firewall_rules" {
  type = list(object({
    id          = string
    name        = string
    action      = string
    direction   = string
    source_vlan = optional(number)
    dest_vlan   = optional(number)
    protocol    = string
    dest_ports  = list(number)
    enabled     = bool
    logging     = bool
  }))
}
