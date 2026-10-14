"""
NetWarden Base Device Driver Interface.
Abstract contract for all multi-brand network drivers.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from netwarden.core.models import (
    NetworkDevice,
    PortInfo,
    VLANDefinition,
    ConnectedClient,
    FirewallRule,
    HardeningFinding,
    DiagnosticResult,
    PortMode,
)


class BaseDeviceDriver(ABC):
    """Abstract interface that every network vendor driver must implement."""

    def __init__(self, device_id: str, name: str, ip: str, **kwargs):
        self.device_id = device_id
        self.name = name
        self.ip = ip
        self.config = kwargs
        self._connected = False

    @abstractmethod
    def connect(self) -> bool:
        """Establish session or authenticate with the device/controller."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close active session or connection."""
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """Return True if device is reachable and credentials are valid."""
        pass

    @abstractmethod
    def get_device_info(self) -> NetworkDevice:
        """Retrieve system details, firmware, uptime, and metadata."""
        pass

    @abstractmethod
    def get_ports(self) -> List[PortInfo]:
        """Retrieve list of physical interfaces, speeds, link status, and VLANs."""
        pass

    @abstractmethod
    def set_port_vlan(
        self, port_number: int, vlan_id: int, mode: PortMode = PortMode.ACCESS
    ) -> bool:
        """Configure native/tagged VLAN assignment on a switch port."""
        pass

    @abstractmethod
    def get_vlans(self) -> List[VLANDefinition]:
        """Retrieve configured VLANs and subnets."""
        pass

    @abstractmethod
    def apply_vlan(self, vlan: VLANDefinition) -> bool:
        """Create or update a VLAN definition on the device."""
        pass

    @abstractmethod
    def get_clients(self) -> List[ConnectedClient]:
        """Retrieve active clients, ARP entries, or DHCP leases."""
        pass

    @abstractmethod
    def allow_client(
        self, mac: str, vlan_id: int, ip: Optional[str] = None, hostname: Optional[str] = None
    ) -> bool:
        """Authorize a device on a specific VLAN with optional static DHCP reservation."""
        pass

    @abstractmethod
    def quarantine_client(self, mac: str, quarantine_vlan_id: int = 99) -> bool:
        """Isolate a rogue or suspect device into an isolated quarantine VLAN."""
        pass

    @abstractmethod
    def block_client(self, mac: str) -> bool:
        """Completely block client by MAC address at switch port or ACL level."""
        pass

    @abstractmethod
    def get_firewall_rules(self) -> List[FirewallRule]:
        """Retrieve active packet filtering and firewall rules."""
        pass

    @abstractmethod
    def apply_firewall_rule(self, rule: FirewallRule) -> bool:
        """Create or update a firewall rule on the router/gateway."""
        pass

    @abstractmethod
    def audit_security(self) -> List[HardeningFinding]:
        """Perform security posture checks (default credentials, unencrypted mgmt, etc.)."""
        pass

    @abstractmethod
    def run_diagnostics(self, target: str) -> DiagnosticResult:
        """Run ICMP ping, ARP resolution, and routing path tests from the device perspective."""
        pass
