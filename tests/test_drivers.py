"""
Unit tests for NetWarden Multi-Brand Device Drivers.
"""

import pytest
from netwarden.drivers import create_driver
from netwarden.core.models import (
    VendorType,
    DeviceType,
    PortMode,
    ClientStatus,
)


def test_mock_driver_ports_and_vlans():
    driver = create_driver(
        vendor=VendorType.UNIFI,
        device_id="sw-test-01",
        name="Test Switch",
        ip="10.0.1.2",
        force_mock=True,
    )
    assert driver.connect() is True
    ports = driver.get_ports()
    assert len(ports) >= 8

    # Test port VLAN modification
    success = driver.set_port_vlan(1, 30, PortMode.ACCESS)
    assert success is True
    updated_ports = {p.port_number: p for p in driver.get_ports()}
    assert updated_ports[1].pvid == 30
    assert updated_ports[1].mode == PortMode.ACCESS


def test_mock_driver_client_lifecycle():
    driver = create_driver(
        vendor=VendorType.MIKROTIK,
        device_id="rtr-test-01",
        name="Test Router",
        ip="10.0.1.1",
        force_mock=True,
    )

    test_mac = "12:34:56:78:9a:bc"
    # Allow client
    driver.allow_client(test_mac, vlan_id=10, ip="10.0.10.77", hostname="Test-Device")
    clients = {c.mac_address: c for c in driver.get_clients()}
    assert test_mac in clients
    assert clients[test_mac].status == ClientStatus.ALLOWED
    assert clients[test_mac].vlan_id == 10

    # Quarantine client
    driver.quarantine_client(test_mac, quarantine_vlan_id=99)
    assert clients[test_mac].status == ClientStatus.QUARANTINED
    assert clients[test_mac].vlan_id == 99

    # Block client
    driver.block_client(test_mac)
    assert clients[test_mac].status == ClientStatus.BLOCKED


def test_driver_diagnostics_cable_check():
    driver = create_driver(
        vendor=VendorType.UNIFI,
        device_id="sw-test-01",
        name="Test Switch",
        ip="10.0.1.2",
        force_mock=True,
    )
    res = driver.run_diagnostics("Hikvision-Camera")
    assert res.reachable is True
    assert res.switch_port_errors > 0
    assert "CRC" in res.root_cause
