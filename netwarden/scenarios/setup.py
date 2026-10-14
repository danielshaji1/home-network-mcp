"""
NetWarden Network Setup & Segmentation Scenario.
Orchestrates initial greenfield network setup, VLANs, subnets, and boundary firewall policies.
"""

from typing import List, Dict, Any, Optional
from netwarden.core.models import (
    VLANDefinition,
    VLANPurpose,
    IsolationLevel,
    FirewallRule,
    RuleAction,
    RuleDirection,
)
from netwarden.core.safety import SafetyGuardrails
from netwarden.core.inventory import NetworkInventory


class SetupScenario:
    """Orchestrates network architecture design, VLAN segmentation, and baseline firewall rules."""

    def __init__(self, inventory: NetworkInventory, safety: Optional[SafetyGuardrails] = None):
        self.inventory = inventory
        self.safety = safety or SafetyGuardrails()

    def generate_segmented_topology(
        self,
        network_profile: str = "standard_home",
        base_subnet_prefix: str = "10.0",
    ) -> Dict[str, Any]:
        """
        Generate a hardened, best-practice VLAN and firewall architecture.
        Profiles: 'standard_home', 'homelab_advanced', 'minimal'.
        """
        vlans = [
            VLANDefinition(
                vlan_id=1,
                name="Management_Infra",
                subnet_cidr=f"{base_subnet_prefix}.1.0/24",
                gateway_ip=f"{base_subnet_prefix}.1.1",
                dhcp_start=f"{base_subnet_prefix}.1.10",
                dhcp_end=f"{base_subnet_prefix}.1.50",
                purpose=VLANPurpose.MANAGEMENT,
                isolation_level=IsolationLevel.RESTRICTED,
                description="Switches, Routers, Access Points, and PDU management plane.",
            ),
            VLANDefinition(
                vlan_id=10,
                name="Trusted_LAN",
                subnet_cidr=f"{base_subnet_prefix}.10.0/24",
                gateway_ip=f"{base_subnet_prefix}.10.1",
                dhcp_start=f"{base_subnet_prefix}.10.100",
                dhcp_end=f"{base_subnet_prefix}.10.250",
                purpose=VLANPurpose.TRUSTED_LAN,
                isolation_level=IsolationLevel.ROUTED,
                description="Admin laptops, personal smartphones, desktop workstations.",
            ),
            VLANDefinition(
                vlan_id=30,
                name="IoT_SmartHome",
                subnet_cidr=f"{base_subnet_prefix}.30.0/24",
                gateway_ip=f"{base_subnet_prefix}.30.1",
                dhcp_start=f"{base_subnet_prefix}.30.50",
                dhcp_end=f"{base_subnet_prefix}.30.250",
                purpose=VLANPurpose.IOT,
                isolation_level=IsolationLevel.INTERNET_ONLY,
                description="Smart plugs, smart speakers, thermostats, IP cameras.",
            ),
            VLANDefinition(
                vlan_id=50,
                name="Guest_Network",
                subnet_cidr=f"{base_subnet_prefix}.50.0/24",
                gateway_ip=f"{base_subnet_prefix}.50.1",
                dhcp_start=f"{base_subnet_prefix}.50.50",
                dhcp_end=f"{base_subnet_prefix}.50.250",
                purpose=VLANPurpose.GUEST,
                isolation_level=IsolationLevel.INTERNET_ONLY,
                description="Visitor mobile devices with strict client-to-client isolation.",
            ),
            VLANDefinition(
                vlan_id=99,
                name="Quarantine_Sandbox",
                subnet_cidr=f"{base_subnet_prefix}.99.0/24",
                gateway_ip=f"{base_subnet_prefix}.99.1",
                dhcp_start=f"{base_subnet_prefix}.99.50",
                dhcp_end=f"{base_subnet_prefix}.99.99",
                purpose=VLANPurpose.QUARANTINE,
                isolation_level=IsolationLevel.ISOLATED,
                description="Isolated containment zone for unapproved or anomalous devices.",
            ),
        ]

        if network_profile == "homelab_advanced":
            vlans.append(
                VLANDefinition(
                    vlan_id=40,
                    name="DMZ_Servers",
                    subnet_cidr=f"{base_subnet_prefix}.40.0/24",
                    gateway_ip=f"{base_subnet_prefix}.40.1",
                    dhcp_start=f"{base_subnet_prefix}.40.50",
                    dhcp_end=f"{base_subnet_prefix}.40.100",
                    purpose=VLANPurpose.DMZ,
                    isolation_level=IsolationLevel.RESTRICTED,
                    description="Reverse proxies, public-facing services, web applications.",
                )
            )

        # Baseline firewall rules
        rules = [
            FirewallRule(
                id="setup-rule-01",
                name="Allow Established and Related",
                action=RuleAction.ACCEPT,
                direction=RuleDirection.FORWARD,
                protocol="any",
                comment="Permits stateful reply packets across all subnets.",
            ),
            FirewallRule(
                id="setup-rule-02",
                name="Allow Trusted LAN to all VLANs",
                action=RuleAction.ACCEPT,
                direction=RuleDirection.FORWARD,
                source_vlan=10,
                protocol="any",
                comment="Workstations can initiate connections to IoT and server segments.",
            ),
            FirewallRule(
                id="setup-rule-03",
                name="Block IoT Access to Private LANs",
                action=RuleAction.DROP,
                direction=RuleDirection.FORWARD,
                source_vlan=30,
                dest_vlan=10,
                protocol="any",
                comment="Stops IoT devices from traversing into trusted workstation networks.",
            ),
            FirewallRule(
                id="setup-rule-04",
                name="Block IoT Access to Router Management",
                action=RuleAction.DROP,
                direction=RuleDirection.FORWARD,
                source_vlan=30,
                dest_vlan=1,
                protocol="tcp",
                dest_ports=[22, 80, 443, 8443, 8291],
                comment="Blocks IoT devices from connecting to switch/router admin portals.",
            ),
            FirewallRule(
                id="setup-rule-05",
                name="Isolate Guest Network from all Private Subnets",
                action=RuleAction.DROP,
                direction=RuleDirection.FORWARD,
                source_vlan=50,
                protocol="any",
                comment="Prevents guest clients from contacting any local internal IP.",
            ),
            FirewallRule(
                id="setup-rule-06",
                name="Completely Blackhole Quarantine VLAN",
                action=RuleAction.DROP,
                direction=RuleDirection.FORWARD,
                source_vlan=99,
                protocol="any",
                comment="Quarantined devices cannot transmit to any internal or external address.",
            ),
        ]

        # Verify against safety guardrails
        self.safety.validate_vlan_modifications(self.inventory.list_vlans(), vlans)
        for r in rules:
            self.safety.validate_firewall_rule(r)

        return {
            "profile": network_profile,
            "vlans": vlans,
            "firewall_rules": rules,
            "summary": (
                f"Generated {len(vlans)} segmented VLANs with zero-trust inter-VLAN boundary "
                f"protection and {len(rules)} firewall policies."
            ),
        }
