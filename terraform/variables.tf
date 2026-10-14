# Global Network Variables for Multi-Brand Declarative Orchestration

variable "vlans" {
  description = "List of VLAN networks and subnet definitions"
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
  default = []
}

variable "allowed_devices" {
  description = "List of authorized client devices with MAC and VLAN bindings"
  type = list(object({
    mac              = string
    hostname         = string
    ip               = optional(string)
    vlan_id          = number
    category         = string
    dhcp_reservation = bool
    switch_port      = optional(number)
  }))
  default = []
}

variable "firewall_rules" {
  description = "Firewall boundary filtering rules"
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
  default = []
}

variable "managed_devices" {
  description = "Inventory of switches, routers, and gateways"
  type = list(object({
    id           = string
    name         = string
    vendor       = string
    device_type  = string
    ip           = string
    active_vlans = list(number)
  }))
  default = []
}
