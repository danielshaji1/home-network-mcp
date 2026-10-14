"""
Unit tests for NetWarden core models and data schemas.
"""

import pytest
from netwarden.core.models import (
    NetworkDevice,
    DeviceType,
    DeviceStatus,
    VendorType,
    PortInfo,
    PortMode,
    VLANDefinition,
    VLANPurpose,
    IsolationLevel,
    ConnectedClient,
    ClientStatus,
    FirewallRule,
    RuleAction,
    RuleDirection,
)


def test_network_device_creation():
    dev = NetworkDevice(
        id="sw-01",
        name="Test Switch",
        vendor=VendorType.UNIFI,
        device_type=DeviceType.SWITCH,
        ip_address="10.0.1.2",
        mac_address="00:11:22:33:44:55",
        status=DeviceStatus.ONLINE,
    )
    assert dev.id == "sw-01"
    assert dev.vendor == VendorType.UNIFI
    assert dev.device_type == DeviceType.SWITCH
    assert dev.status == DeviceStatus.ONLINE


def test_vlan_definition_validation():
    vlan = VLANDefinition(
        vlan_id=30,
        name="IoT_Isolation",
        subnet_cidr="10.0.30.0/24",
        gateway_ip="10.0.30.1",
        dhcp_start="10.0.30.50",
        dhcp_end="10.0.30.200",
        purpose=VLANPurpose.IOT,
        isolation_level=IsolationLevel.INTERNET_ONLY,
    )
    assert vlan.vlan_id == 30
    assert vlan.purpose == VLANPurpose.IOT
    assert vlan.isolation_level == IsolationLevel.INTERNET_ONLY


def test_connected_client_defaults():
    client = ConnectedClient(
        mac_address="AA:BB:CC:DD:EE:FF",
        hostname="Laptop-01",
        vlan_id=10,
    )
    assert client.status == ClientStatus.ALLOWED
    assert client.dhcp_reservation is False
    assert client.first_seen is not None


def test_firewall_rule_serialization():
    rule = FirewallRule(
        id="rule-test",
        name="Block IoT to LAN",
        action=RuleAction.DROP,
        direction=RuleDirection.FORWARD,
        source_vlan=30,
        dest_vlan=10,
        protocol="any",
    )
    dumped = rule.model_dump()
    assert dumped["action"] == "drop"
    assert dumped["source_vlan"] == 30
    assert dumped["dest_vlan"] == 10
