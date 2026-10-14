"""
Unit tests for NetWarden safety guardrails and lockout prevention engine.
"""

import pytest
from netwarden.core.safety import SafetyGuardrails
from netwarden.core.exceptions import SafetyLockoutError
from netwarden.core.models import (
    ConnectedClient,
    ClientStatus,
    FirewallRule,
    RuleAction,
    RuleDirection,
    VLANDefinition,
    VLANPurpose,
)


@pytest.fixture
def safety():
    return SafetyGuardrails(
        protected_ips=["10.0.1.1", "10.0.10.105"],
        protected_macs=["00:11:22:33:44:01"],
        management_vlan_id=1,
    )


def test_lockout_prevents_blocking_admin_mac(safety):
    admin_client = ConnectedClient(
        mac_address="00:11:22:33:44:01",
        hostname="Admin-MacBook",
        ip_address="10.0.10.105",
        vlan_id=10,
    )
    with pytest.raises(SafetyLockoutError) as exc_info:
        safety.validate_client_action(admin_client, ClientStatus.BLOCKED)
    assert "administrative lockout" in str(exc_info.value).lower()


def test_lockout_prevents_quarantining_admin_mac(safety):
    admin_client = ConnectedClient(
        mac_address="00:11:22:33:44:01",
        hostname="Admin-MacBook",
        ip_address="10.0.10.105",
        vlan_id=10,
    )
    with pytest.raises(SafetyLockoutError):
        safety.validate_client_action(admin_client, ClientStatus.QUARANTINED)


def test_lockout_allows_quarantining_rogue_mac(safety):
    rogue = ConnectedClient(
        mac_address="ff:ee:dd:cc:bb:aa",
        hostname="unknown-intruder",
        vlan_id=1,
    )
    # Should not raise exception
    safety.validate_client_action(rogue, ClientStatus.QUARANTINED)


def test_lockout_prevents_dropping_management_vlan(safety):
    rule = FirewallRule(
        id="bad-rule",
        name="Drop all to Management",
        action=RuleAction.DROP,
        direction=RuleDirection.FORWARD,
        dest_vlan=1,
        source_ip_or_cidr="0.0.0.0/0",
    )
    with pytest.raises(SafetyLockoutError) as exc_info:
        safety.validate_firewall_rule(rule)
    assert "management" in str(exc_info.value).lower()


def test_vlan_modification_prevents_deleting_management_vlan(safety):
    current = [
        VLANDefinition(
            vlan_id=1,
            name="Mgmt",
            subnet_cidr="10.0.1.0/24",
            gateway_ip="10.0.1.1",
            dhcp_start="10.0.1.10",
            dhcp_end="10.0.1.50",
            purpose=VLANPurpose.MANAGEMENT,
        )
    ]
    proposed_without_mgmt = [
        VLANDefinition(
            vlan_id=10,
            name="Trusted",
            subnet_cidr="10.0.10.0/24",
            gateway_ip="10.0.10.1",
            dhcp_start="10.0.10.10",
            dhcp_end="10.0.10.50",
            purpose=VLANPurpose.TRUSTED_LAN,
        )
    ]
    with pytest.raises(SafetyLockoutError) as exc_info:
        safety.validate_vlan_modifications(current, proposed_without_mgmt)
    assert "management vlan" in str(exc_info.value).lower()


def test_vlan_subnet_collision_detection(safety):
    colliding = [
        VLANDefinition(
            vlan_id=1,
            name="Mgmt",
            subnet_cidr="10.0.1.0/24",
            gateway_ip="10.0.1.1",
            dhcp_start="10.0.1.10",
            dhcp_end="10.0.1.50",
            purpose=VLANPurpose.MANAGEMENT,
        ),
        VLANDefinition(
            vlan_id=2,
            name="Conflicting",
            subnet_cidr="10.0.0.0/16",  # Overlaps 10.0.1.0/24
            gateway_ip="10.0.0.1",
            dhcp_start="10.0.0.10",
            dhcp_end="10.0.0.50",
            purpose=VLANPurpose.TRUSTED_LAN,
        ),
    ]
    with pytest.raises(SafetyLockoutError) as exc_info:
        safety.validate_vlan_modifications([], colliding)
    assert "overlaps" in str(exc_info.value).lower()
