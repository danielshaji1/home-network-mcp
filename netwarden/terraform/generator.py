"""
NetWarden Terraform Manifest & Variables Generator.
Translates high-level network topology into declarative Terraform HCL & JSON inputs.
"""

from typing import List, Dict, Any
import json
from pathlib import Path
from netwarden.core.models import (
    VLANDefinition,
    ConnectedClient,
    FirewallRule,
    NetworkDevice,
)


class TerraformGenerator:
    """Generates declarative Terraform configuration files and variables."""

    def __init__(self, output_dir: str = "./terraform"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_tfvars(
        self,
        vlans: List[VLANDefinition],
        clients: List[ConnectedClient],
        firewall_rules: List[FirewallRule],
        devices: List[NetworkDevice],
    ) -> Path:
        """Generate network.tfvars.json containing all declarative state variables."""
        tfvars_data: Dict[str, Any] = {
            "vlans": [
                {
                    "vlan_id": v.vlan_id,
                    "name": v.name,
                    "subnet_cidr": v.subnet_cidr,
                    "gateway_ip": v.gateway_ip,
                    "dhcp_start": v.dhcp_start,
                    "dhcp_end": v.dhcp_end,
                    "purpose": v.purpose.value,
                    "isolation_level": v.isolation_level.value,
                    "dns_servers": v.dns_servers,
                }
                for v in vlans
            ],
            "allowed_devices": [
                {
                    "mac": c.mac_address,
                    "hostname": c.hostname or f"device-{c.mac_address.replace(':', '')[-4:]}",
                    "ip": c.ip_address,
                    "vlan_id": c.vlan_id,
                    "category": c.device_category,
                    "dhcp_reservation": c.dhcp_reservation,
                    "switch_port": c.switch_port,
                }
                for c in clients
                if c.status.value == "allowed"
            ],
            "firewall_rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "action": r.action.value,
                    "direction": r.direction.value,
                    "source_vlan": r.source_vlan,
                    "dest_vlan": r.dest_vlan,
                    "protocol": r.protocol,
                    "dest_ports": r.dest_ports,
                    "enabled": r.enabled,
                    "logging": r.logging,
                }
                for r in firewall_rules
            ],
            "managed_devices": [
                {
                    "id": d.id,
                    "name": d.name,
                    "vendor": d.vendor.value,
                    "device_type": d.device_type.value,
                    "ip": d.ip_address,
                    "active_vlans": d.active_vlans,
                }
                for d in devices
            ],
        }

        tfvars_path = self.output_dir / "network.tfvars.json"
        with open(tfvars_path, "w", encoding="utf-8") as f:
            json.dump(tfvars_data, f, indent=2)

        return tfvars_path

    def generate_hcl_summary(self, vlans: List[VLANDefinition], clients: List[ConnectedClient]) -> str:
        """Produce a readable HCL snippet preview."""
        hcl_lines = ["# Auto-Generated NetWarden Declarative Topology", ""]
        for v in vlans:
            hcl_lines.append(f'vlan "{v.name}" {{')
            hcl_lines.append(f"  id        = {v.vlan_id}")
            hcl_lines.append(f'  subnet    = "{v.subnet_cidr}"')
            hcl_lines.append(f'  gateway   = "{v.gateway_ip}"')
            hcl_lines.append(f'  isolation = "{v.isolation_level.value}"')
            hcl_lines.append("}\n")

        hcl_lines.append("# Authorized Static Clients")
        for c in clients:
            if c.status.value == "allowed":
                hcl_lines.append(f'client "{c.hostname or c.mac_address}" {{')
                hcl_lines.append(f'  mac     = "{c.mac_address}"')
                hcl_lines.append(f"  vlan_id = {c.vlan_id}")
                if c.ip_address:
                    hcl_lines.append(f'  ip      = "{c.ip_address}"')
                hcl_lines.append("}\n")

        return "\n".join(hcl_lines)
