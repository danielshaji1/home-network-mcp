"""
NetWarden Device Allowlisting & Access Control Scenario.
Handles zero-trust authorization, VLAN assignment, static DHCP binding, and quarantine.
"""

from typing import List, Dict, Any, Optional
from netwarden.core.models import (
    ConnectedClient,
    ClientStatus,
)
from netwarden.core.safety import SafetyGuardrails
from netwarden.core.inventory import NetworkInventory
from netwarden.drivers.base import BaseDeviceDriver


class AllowlistScenario:
    """Manages allowed devices, static reservations, and isolation across multi-brand equipment."""

    def __init__(
        self,
        inventory: NetworkInventory,
        drivers: Optional[List[BaseDeviceDriver]] = None,
        safety: Optional[SafetyGuardrails] = None,
    ):
        self.inventory = inventory
        self.drivers = drivers or []
        self.safety = safety or SafetyGuardrails()

    def list_clients(self, status_filter: Optional[str] = None) -> List[ConnectedClient]:
        """List known clients, optionally filtering by allowed, pending_approval, quarantined, blocked."""
        if status_filter:
            try:
                target_status = ClientStatus(status_filter.lower())
                return self.inventory.list_clients(status=target_status)
            except ValueError:
                pass
        return self.inventory.list_clients()

    def allow_device(
        self,
        mac_address: str,
        vlan_id: int,
        hostname: Optional[str] = None,
        ip_reservation: Optional[str] = None,
        category: str = "General",
    ) -> Dict[str, Any]:
        """Authorize a device on a specified VLAN with optional static DHCP IP reservation."""
        client = self.inventory.get_client(mac_address)
        if not client:
            client = ConnectedClient(
                mac_address=mac_address.lower(),
                ip_address=ip_reservation,
                hostname=hostname,
                vlan_id=vlan_id,
                device_category=category,
                status=ClientStatus.ALLOWED,
                dhcp_reservation=bool(ip_reservation),
            )
            self.inventory.add_client(client)
        else:
            client.status = ClientStatus.ALLOWED
            client.vlan_id = vlan_id
            if hostname:
                client.hostname = hostname
            if ip_reservation:
                client.ip_address = ip_reservation
                client.dhcp_reservation = True
            client.device_category = category

        self.inventory.save()

        # Update physical drivers
        driver_results = []
        for d in self.drivers:
            res = d.allow_client(mac_address, vlan_id, ip_reservation, hostname)
            driver_results.append({"device": d.name, "success": res})

        return {
            "success": True,
            "mac_address": client.mac_address,
            "hostname": client.hostname,
            "vlan_id": client.vlan_id,
            "ip_reservation": client.ip_address,
            "status": client.status.value,
            "hardware_updates": driver_results,
        }

    def quarantine_device(self, mac_address: str, quarantine_vlan_id: int = 99) -> Dict[str, Any]:
        """Isolate a device into the quarantine sandbox VLAN."""
        client = self.inventory.get_client(mac_address)
        if not client:
            client = ConnectedClient(
                mac_address=mac_address.lower(),
                vlan_id=quarantine_vlan_id,
                status=ClientStatus.QUARANTINED,
            )
            self.inventory.add_client(client)

        # Enforce safety guardrails against administrative lockout
        self.safety.validate_client_action(client, ClientStatus.QUARANTINED)

        client.status = ClientStatus.QUARANTINED
        client.vlan_id = quarantine_vlan_id
        self.inventory.save()

        driver_results = []
        for d in self.drivers:
            res = d.quarantine_client(mac_address, quarantine_vlan_id)
            driver_results.append({"device": d.name, "quarantined": res})

        return {
            "success": True,
            "mac_address": client.mac_address,
            "action": "QUARANTINED",
            "vlan_id": quarantine_vlan_id,
            "hardware_updates": driver_results,
        }

    def block_device(self, mac_address: str) -> Dict[str, Any]:
        """Completely block device from network access."""
        client = self.inventory.get_client(mac_address)
        if not client:
            client = ConnectedClient(
                mac_address=mac_address.lower(),
                status=ClientStatus.BLOCKED,
            )
            self.inventory.add_client(client)

        # Safety check
        self.safety.validate_client_action(client, ClientStatus.BLOCKED)

        client.status = ClientStatus.BLOCKED
        self.inventory.save()

        driver_results = []
        for d in self.drivers:
            res = d.block_client(mac_address)
            driver_results.append({"device": d.name, "blocked": res})

        return {
            "success": True,
            "mac_address": client.mac_address,
            "action": "BLOCKED",
            "hardware_updates": driver_results,
        }
