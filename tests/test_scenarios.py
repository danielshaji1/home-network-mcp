"""
Unit tests for NetWarden Scenarios: Setup, Hardening, Allowlist, and Troubleshooting.
"""

import pytest
from netwarden.core.inventory import NetworkInventory
from netwarden.core.safety import SafetyGuardrails
from netwarden.core.models import (
    ConnectedClient,
    ClientStatus,
    VLANDefinition,
    VLANPurpose,
    FirewallRule,
    RuleAction,
    RuleDirection,
)
from netwarden.drivers.mock import MockDeviceDriver
from netwarden.scenarios import (
    SetupScenario,
    HardeningScenario,
    AllowlistScenario,
    TroubleshootingScenario,
)


@pytest.fixture
def test_env(tmp_path):
    persistence = str(tmp_path / "test_state.json")
    inv = NetworkInventory(persistence)
    safety = SafetyGuardrails(
        protected_ips=["10.0.1.1", "10.0.10.105"],
        protected_macs=["00:11:22:33:44:01"],
        management_vlan_id=1,
    )
    drv = MockDeviceDriver(
        device_id="sw-01",
        name="Mock Switch",
        ip="10.0.1.2",
    )
    for v in drv.get_vlans():
        inv.add_vlan(v)
    for c in drv.get_clients():
        inv.add_client(c)
    for r in drv.get_firewall_rules():
        inv.add_firewall_rule(r)

    return {
        "inv": inv,
        "safety": safety,
        "driver": drv,
    }


def test_setup_scenario(test_env):
    setup = SetupScenario(test_env["inv"], test_env["safety"])
    topology = setup.generate_segmented_topology("homelab_advanced", base_subnet_prefix="10.0")

    vlans = topology["vlans"]
    vlan_ids = [v.vlan_id for v in vlans]
    assert 1 in vlan_ids   # Management
    assert 10 in vlan_ids  # Trusted LAN
    assert 30 in vlan_ids  # IoT
    assert 40 in vlan_ids  # DMZ (homelab)
    assert 50 in vlan_ids  # Guest
    assert 99 in vlan_ids  # Quarantine


def test_hardening_scenario_audit_and_remediation(test_env):
    hardening = HardeningScenario(test_env["inv"], [test_env["driver"]])
    report = hardening.run_security_audit()

    assert report.total_findings > 0
    assert report.overall_score < 100

    # Test auto-remediation
    rem_res = hardening.apply_remediation()
    assert rem_res["remediated_count"] >= 1
    assert rem_res["new_audit_score"] > report.overall_score


def test_allowlist_scenario_actions(test_env):
    allowlist = AllowlistScenario(test_env["inv"], [test_env["driver"]], test_env["safety"])

    # Allow
    allow_res = allowlist.allow_device(
        mac_address="aa:11:22:33:44:55",
        vlan_id=30,
        hostname="New-IoT-Thermostat",
        ip_reservation="10.0.30.90",
        category="IoT",
    )
    assert allow_res["success"] is True
    assert allow_res["status"] == "allowed"

    # Quarantine
    q_res = allowlist.quarantine_device("aa:11:22:33:44:55", quarantine_vlan_id=99)
    assert q_res["success"] is True
    assert q_res["vlan_id"] == 99

    # Block
    b_res = allowlist.block_device("aa:11:22:33:44:55")
    assert b_res["success"] is True
    assert b_res["action"] == "BLOCKED"


def test_troubleshooting_switch_port_inspection(test_env):
    troubleshooting = TroubleshootingScenario(test_env["inv"], [test_env["driver"]])
    anomalies = troubleshooting.inspect_switch_ports()

    # Port 3 has CRC errors in mock switch
    assert len(anomalies) >= 1
    port_3_issue = [a for a in anomalies if a["port_number"] == 3][0]
    assert port_3_issue["crc_errors"] > 0
    assert "cable" in port_3_issue["suggested_fix"].lower()


def test_troubleshooting_firewall_trace(test_env):
    troubleshooting = TroubleshootingScenario(test_env["inv"], [test_env["driver"]])
    # IoT (VLAN 30) to Trusted LAN (VLAN 10) is blocked by rule-200
    res = troubleshooting.trace_inter_vlan_path(30, 10)
    assert res["traffic_allowed"] is False
    assert "Isolate IoT from Private LANs" in res["blocking_rule_name"]
