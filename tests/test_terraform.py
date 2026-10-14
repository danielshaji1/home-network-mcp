"""
Unit tests for NetWarden Terraform Engine, Generator, and State Manager.
"""

import pytest
import json
from pathlib import Path
from netwarden.core.models import (
    VLANDefinition,
    VLANPurpose,
    IsolationLevel,
    ConnectedClient,
    FirewallRule,
    RuleAction,
    NetworkDevice,
    VendorType,
    DeviceType,
)
from netwarden.terraform import TerraformGenerator, TerraformRunner, StateManager


@pytest.fixture
def sample_data():
    vlans = [
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
            vlan_id=30,
            name="IoT",
            subnet_cidr="10.0.30.0/24",
            gateway_ip="10.0.30.1",
            dhcp_start="10.0.30.50",
            dhcp_end="10.0.30.200",
            purpose=VLANPurpose.IOT,
            isolation_level=IsolationLevel.INTERNET_ONLY,
        ),
    ]
    clients = [
        ConnectedClient(
            mac_address="00:11:22:33:44:01",
            hostname="Admin-Laptop",
            ip_address="10.0.1.20",
            vlan_id=1,
            dhcp_reservation=True,
        )
    ]
    rules = [
        FirewallRule(
            id="rule-test",
            name="Block IoT to LAN",
            action=RuleAction.DROP,
            source_vlan=30,
            dest_vlan=1,
        )
    ]
    devices = [
        NetworkDevice(
            id="sw-01",
            name="Switch 01",
            vendor=VendorType.UNIFI,
            device_type=DeviceType.SWITCH,
            ip_address="10.0.1.2",
            mac_address="00:11:22:33:44:55",
        )
    ]
    return vlans, clients, rules, devices


def test_terraform_generator(tmp_path, sample_data):
    vlans, clients, rules, devices = sample_data
    generator = TerraformGenerator(output_dir=str(tmp_path))
    tfvars_file = generator.generate_tfvars(vlans, clients, rules, devices)

    assert tfvars_file.exists()
    with open(tfvars_file, "r") as f:
        data = json.load(f)

    assert len(data["vlans"]) == 2
    assert len(data["allowed_devices"]) == 1
    assert data["allowed_devices"][0]["hostname"] == "Admin-Laptop"


def test_terraform_runner_simulation(tmp_path, sample_data):
    vlans, clients, rules, devices = sample_data
    generator = TerraformGenerator(output_dir=str(tmp_path))
    generator.generate_tfvars(vlans, clients, rules, devices)

    runner = TerraformRunner(working_dir=str(tmp_path))
    init_res = runner.init()
    assert "initialized" in init_res.lower()

    plan_res = runner.plan()
    assert plan_res.resources_to_add >= 1
    assert plan_res.is_safe_to_apply is True

    apply_res = runner.apply()
    assert apply_res["success"] is True


def test_state_manager_snapshots(tmp_path):
    sm = StateManager(backup_dir=str(tmp_path / "backups"))
    state_payload = {"test_vlan": 10, "name": "Trusted"}

    snap_id = sm.create_snapshot("Initial test checkpoint", state_payload)
    assert snap_id.startswith("snap_")

    snapshots = sm.list_snapshots()
    assert len(snapshots) == 1
    assert snapshots[0]["snapshot_id"] == snap_id

    loaded = sm.get_snapshot(snap_id)
    assert loaded["state"]["test_vlan"] == 10
