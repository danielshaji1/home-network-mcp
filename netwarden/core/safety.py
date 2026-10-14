"""
NetWarden Safety Guardrails and Lockout Prevention Engine.
Protects network administrators from accidental disconnection and destructive modifications.
"""

from typing import List, Tuple, Optional
import ipaddress
from netwarden.core.models import (
    NetworkDevice,
    VLANDefinition,
    FirewallRule,
    RuleAction,
    ConnectedClient,
    ClientStatus,
)
from netwarden.core.exceptions import SafetyLockoutError


class SafetyGuardrails:
    """
    Enforces critical network safety invariants:
    - Never isolate the management VLAN or drop access to management IPs.
    - Never block or quarantine administrative MAC addresses.
    - Never delete the primary gateway uplink.
    - Validate CIDR ranges against overlap or misconfiguration.
    """

    def __init__(
        self,
        protected_ips: Optional[List[str]] = None,
        protected_macs: Optional[List[str]] = None,
        management_vlan_id: int = 1,
    ):
        # Default protected IPs (e.g. gateway and common admin workstations)
        self.protected_ips = protected_ips or [
            "127.0.0.1",
            "192.168.1.1",
            "10.0.1.1",
            "10.0.0.1",
        ]
        # Admin MAC addresses that must NEVER be blocked or quarantined
        self.protected_macs = [mac.lower() for mac in (protected_macs or [])]
        self.management_vlan_id = management_vlan_id

    def add_protected_mac(self, mac: str) -> None:
        self.protected_macs.append(mac.lower())

    def add_protected_ip(self, ip: str) -> None:
        self.protected_ips.append(ip)

    def validate_client_action(self, client: ConnectedClient, target_status: ClientStatus) -> None:
        """Ensure administrative clients are never blocked or quarantined."""
        normalized_mac = client.mac_address.lower()
        if target_status in [ClientStatus.BLOCKED, ClientStatus.QUARANTINED]:
            if normalized_mac in self.protected_macs:
                raise SafetyLockoutError(
                    f"Action Rejected: MAC {client.mac_address} ({client.hostname or 'Admin'}) "
                    f"is registered as a protected administrative device. Blocking or quarantining it "
                    f"would cause administrative lockout."
                )
            if client.ip_address and client.ip_address in self.protected_ips:
                raise SafetyLockoutError(
                    f"Action Rejected: IP {client.ip_address} is a protected administrative address."
                )

    def validate_firewall_rule(self, rule: FirewallRule) -> None:
        """Prevent firewall rules that would sever administrator access."""
        if rule.action in [RuleAction.DROP, RuleAction.REJECT]:
            # Check if rule drops traffic to management VLAN
            if rule.dest_vlan == self.management_vlan_id and (rule.dest_ports == [] or 22 in rule.dest_ports or 443 in rule.dest_ports or 8443 in rule.dest_ports):
                if rule.source_vlan is None and (rule.source_ip_or_cidr is None or "0.0.0.0/0" in rule.source_ip_or_cidr):
                    raise SafetyLockoutError(
                        f"Action Rejected: Firewall rule '{rule.name}' would drop all traffic to "
                        f"Management VLAN {self.management_vlan_id} including SSH and HTTPS management ports!"
                    )
                if rule.source_vlan == self.management_vlan_id:
                    raise SafetyLockoutError(
                        f"Action Rejected: Firewall rule '{rule.name}' drops traffic originating from Management VLAN {self.management_vlan_id}."
                    )

            # Check if rule explicitly drops a protected IP
            if rule.dest_ip_or_cidr:
                for prot_ip in self.protected_ips:
                    if prot_ip == rule.dest_ip_or_cidr:
                        raise SafetyLockoutError(
                            f"Action Rejected: Firewall rule '{rule.name}' explicitly drops protected management IP {prot_ip}."
                        )

    def validate_vlan_modifications(
        self, current_vlans: List[VLANDefinition], proposed_vlans: List[VLANDefinition]
    ) -> None:
        """Ensure management VLAN is not accidentally removed and subnets do not conflict."""
        proposed_vlan_ids = {v.vlan_id for v in proposed_vlans}
        if self.management_vlan_id not in proposed_vlan_ids:
            raise SafetyLockoutError(
                f"Action Rejected: Proposed VLAN topology removes the designated Management VLAN "
                f"(ID: {self.management_vlan_id}). This will disconnect network management tools!"
            )

        # Check for subnet overlap
        subnets = []
        for v in proposed_vlans:
            try:
                net = ipaddress.ip_network(v.subnet_cidr, strict=False)
                for existing_net in subnets:
                    if net.overlaps(existing_net):
                        raise SafetyLockoutError(
                            f"Subnet Conflict: VLAN {v.vlan_id} ({v.subnet_cidr}) overlaps with {existing_net}."
                        )
                subnets.append(net)
            except ValueError as e:
                raise SafetyLockoutError(f"Invalid CIDR '{v.subnet_cidr}' in VLAN {v.vlan_id}: {e}")

    def assess_risk(self, changes: List[str]) -> Tuple[str, List[str]]:
        """
        Assess risk of an operation based on keywords and operations.
        Returns (risk_level, list_of_warnings).
        """
        warnings = []
        high_risk_keywords = ["drop", "quarantine", "vlan delete", "firmware", "reboot", "factory"]
        medium_risk_keywords = ["firewall", "subnet", "dhcp", "isolate", "trunk"]

        has_high = False
        has_med = False

        for change in changes:
            lower_c = change.lower()
            for kw in high_risk_keywords:
                if kw in lower_c:
                    has_high = True
                    warnings.append(f"High risk operation detected: '{change}'")
            for kw in medium_risk_keywords:
                if kw in lower_c:
                    has_med = True
                    warnings.append(f"Moderate risk operation detected: '{change}'")

        if has_high:
            return "HIGH", warnings
        elif has_med:
            return "MEDIUM", warnings
        return "LOW", warnings
