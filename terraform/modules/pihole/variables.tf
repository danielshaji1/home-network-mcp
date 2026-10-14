variable "allowed_devices" {
  type = list(object({
    mac              = string
    hostname         = string
    ip               = optional(string)
    vlan_id          = number
    category         = string
    dhcp_reservation = bool
    switch_port      = optional(number)
  }))
}
