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
