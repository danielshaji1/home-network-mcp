"""
NetWarden Network Inventory and State Database.
Maintains state across multi-brand devices, clients, VLANs, and firewall rules with JSON disk persistence.
"""

from typing import Dict, List, Optional
from pathlib import Path
import json
from netwarden.core.models import (
    NetworkDevice,
    ConnectedClient,
    VLANDefinition,
    FirewallRule,
    ClientStatus,
)


class NetworkInventory:
    """Network inventory with fast indexing by IP, MAC, ID, and VLAN, plus disk persistence."""

    def __init__(self, persistence_file: str = ".netwarden_state.json"):
        self.persistence_file = Path(persistence_file)
        self.devices: Dict[str, NetworkDevice] = {}
        self.clients: Dict[str, ConnectedClient] = {}  # Keyed by MAC address
        self.vlans: Dict[int, VLANDefinition] = {}     # Keyed by VLAN ID
        self.firewall_rules: Dict[str, FirewallRule] = {} # Keyed by Rule ID

    def add_device(self, device: NetworkDevice) -> None:
        self.devices[device.id] = device
        self.save()

    def get_device(self, device_id: str) -> Optional[NetworkDevice]:
        return self.devices.get(device_id)

    def list_devices(self) -> List[NetworkDevice]:
        return list(self.devices.values())

    def add_client(self, client: ConnectedClient) -> None:
        self.clients[client.mac_address.lower()] = client
        self.save()

    def get_client(self, mac_address: str) -> Optional[ConnectedClient]:
        return self.clients.get(mac_address.lower())

    def list_clients(self, status: Optional[ClientStatus] = None) -> List[ConnectedClient]:
        if status:
            return [c for c in self.clients.values() if c.status == status]
        return list(self.clients.values())

    def add_vlan(self, vlan: VLANDefinition) -> None:
        self.vlans[vlan.vlan_id] = vlan
        self.save()

    def get_vlan(self, vlan_id: int) -> Optional[VLANDefinition]:
        return self.vlans.get(vlan_id)

    def list_vlans(self) -> List[VLANDefinition]:
        return sorted(list(self.vlans.values()), key=lambda v: v.vlan_id)

    def add_firewall_rule(self, rule: FirewallRule) -> None:
        self.firewall_rules[rule.id] = rule
        self.save()

    def list_firewall_rules(self) -> List[FirewallRule]:
        return list(self.firewall_rules.values())

    def find_client_by_ip_or_mac(self, identifier: str) -> Optional[ConnectedClient]:
        id_lower = identifier.lower()
        if id_lower in self.clients:
            return self.clients[id_lower]
        for client in self.clients.values():
            if client.ip_address == identifier or client.hostname == identifier:
                return client
        return None

    def save(self) -> None:
        """Persist state to JSON file."""
        try:
            data = {
                "devices": [d.model_dump(mode="json") for d in self.devices.values()],
                "clients": [c.model_dump(mode="json") for c in self.clients.values()],
                "vlans": [v.model_dump(mode="json") for v in self.vlans.values()],
                "firewall_rules": [r.model_dump(mode="json") for r in self.firewall_rules.values()],
            }
            with open(self.persistence_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def load(self) -> bool:
        """Load state from JSON file if present."""
        if not self.persistence_file.exists():
            return False
        try:
            with open(self.persistence_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for d in data.get("devices", []):
                    dev = NetworkDevice(**d)
                    self.devices[dev.id] = dev
                for c in data.get("clients", []):
                    client = ConnectedClient(**c)
                    self.clients[client.mac_address.lower()] = client
                for v in data.get("vlans", []):
                    vlan = VLANDefinition(**v)
                    self.vlans[vlan.vlan_id] = vlan
                for r in data.get("firewall_rules", []):
                    rule = FirewallRule(**r)
                    self.firewall_rules[rule.id] = rule
            return True
        except Exception:
            return False
