"""
Integration tests for NetWarden MCP Server tools.
"""

import pytest
import json
from netwarden.server import (
    app,
    get_network_topology,
    get_device_details,
    list_connected_clients,
    approve_and_allow_device,
    quarantine_device,
    audit_network_security,
    diagnose_device_connectivity,
    check_switch_port_health,
    generate_terraform_plan,
    apply_terraform_configuration,
)


def test_mcp_get_network_topology():
    res_str = get_network_topology()
    data = json.loads(res_str)
    assert "devices" in data
    assert "vlans" in data
    assert data["device_count"] >= 3


def test_mcp_device_details():
    res_str = get_device_details("sw-core-01")
    data = json.loads(res_str)
    assert data["id"] == "sw-core-01"
    assert "ports" in data


def test_mcp_client_allowlist_lifecycle():
    # 1. Allow
    allow_json = approve_and_allow_device(
        mac_address="00:aa:bb:cc:dd:ee",
        vlan_id=10,
        hostname="New-MacBook",
        ip_reservation="10.0.10.88",
    )
    allow_data = json.loads(allow_json)
    assert allow_data["success"] is True

    # 2. List
    clients_json = list_connected_clients()
    clients = json.loads(clients_json)
    macs = [c["mac_address"] for c in clients]
    assert "00:aa:bb:cc:dd:ee" in macs

    # 3. Quarantine
    q_json = quarantine_device("00:aa:bb:cc:dd:ee")
    q_data = json.loads(q_json)
    assert q_data["action"] == "QUARANTINED"


def test_mcp_security_audit():
    audit_json = audit_network_security()
    audit_data = json.loads(audit_json)
    assert "overall_score" in audit_data
    assert "findings" in audit_data


def test_mcp_diagnostics():
    diag_json = diagnose_device_connectivity("1.1.1.1")
    diag_data = json.loads(diag_json)
    assert diag_data["reachable"] is True


def test_mcp_switch_port_health():
    health_json = check_switch_port_health()
    health_data = json.loads(health_json)
    assert "anomalies_detected" in health_data


def test_mcp_terraform_plan_and_apply():
    plan_json = generate_terraform_plan()
    plan_data = json.loads(plan_json)
    assert "plan_summary" in plan_data
    assert plan_data["plan_summary"]["is_safe_to_apply"] is True

    apply_json = apply_terraform_configuration()
    apply_data = json.loads(apply_json)
    assert apply_data["success"] is True
    assert "rollback_snapshot_id" in apply_data
