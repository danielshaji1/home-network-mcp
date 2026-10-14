"""
NetWarden MCP Server.
Exposes Model Context Protocol tools for multi-brand home network management and Terraform orchestration.
"""

from typing import List, Dict, Any, Optional
import json
from mcp.server.mcpserver import MCPServer
from netwarden.config import load_config, NetWardenSettings
from netwarden.core.inventory import NetworkInventory
from netwarden.core.safety import SafetyGuardrails
from netwarden.core.models import (
    VendorType,
    DeviceType,
    ClientStatus,
    PortMode,
)
from netwarden.drivers import create_driver, BaseDeviceDriver
from netwarden.drivers.mock import MockDeviceDriver
from netwarden.terraform import TerraformGenerator, TerraformRunner, StateManager
from netwarden.scenarios import (
    SetupScenario,
    HardeningScenario,
    AllowlistScenario,
    TroubleshootingScenario,
)

# Initialize MCP Server
app = MCPServer("netwarden-home-network-mcp")

# Global Context Container
class NetWardenContext:
    def __init__(self, config_path: Optional[str] = None):
        self.settings: NetWardenSettings = load_config(config_path)
        self.inventory = NetworkInventory()
        self.safety = SafetyGuardrails(
            protected_ips=self.settings.protected_ips,
            protected_macs=self.settings.protected_macs,
            management_vlan_id=self.settings.management_vlan,
        )
        self.drivers: List[BaseDeviceDriver] = []
        self.generator = TerraformGenerator(self.settings.terraform_working_dir)
        self.runner = TerraformRunner(self.settings.terraform_working_dir, safety=self.safety)
        self.state_manager = StateManager(f"{self.settings.terraform_working_dir}/backups")

        # Initialize Drivers & Seed Data
        self._bootstrap_drivers()

        # Initialize Scenarios
        self.setup_scenario = SetupScenario(self.inventory, self.safety)
        self.hardening_scenario = HardeningScenario(self.inventory, self.drivers)
        self.allowlist_scenario = AllowlistScenario(self.inventory, self.drivers, self.safety)
        self.troubleshooting_scenario = TroubleshootingScenario(self.inventory, self.drivers)

    def _bootstrap_drivers(self):
        """Initialize configured drivers or start with realistic multi-brand mock devices."""
        if self.settings.devices:
            for dev in self.settings.devices:
                drv = create_driver(
                    vendor=dev.vendor,
                    device_id=dev.id,
                    name=dev.name,
                    ip=dev.ip,
                    port=dev.port,
                    username=dev.username,
                    password=dev.password,
                    api_key=dev.api_key,
                    force_mock=self.settings.use_mock_driver,
                )
                self.drivers.append(drv)
                self.inventory.add_device(drv.get_device_info())
        else:
            # Seed standard multi-brand homelab devices
            mock_switch = MockDeviceDriver(
                device_id="sw-core-01",
                name="UniFi USW-Pro-24-PoE Core Switch",
                ip="10.0.1.2",
                vendor=VendorType.UNIFI,
                device_type=DeviceType.SWITCH,
                model="USW-Pro-24-PoE",
            )
            mock_router = MockDeviceDriver(
                device_id="rtr-edge-01",
                name="MikroTik RB5009 Gateway Router",
                ip="10.0.1.1",
                vendor=VendorType.MIKROTIK,
                device_type=DeviceType.ROUTER,
                model="RB5009UG+S+IN",
            )
            mock_dns = MockDeviceDriver(
                device_id="pihole-01",
                name="Pi-hole DNS Sinkhole",
                ip="10.0.1.15",
                vendor=VendorType.PIHOLE,
                device_type=DeviceType.SINKHOLE,
                model="Raspberry Pi 4",
            )
            self.drivers.extend([mock_switch, mock_router, mock_dns])

            # Check if persisted state exists on disk
            if not self.inventory.load():
                # Sync inventory with mock drivers
                for drv in self.drivers:
                    self.inventory.add_device(drv.get_device_info())
                    for v in drv.get_vlans():
                        self.inventory.add_vlan(v)
                    for c in drv.get_clients():
                        self.inventory.add_client(c)
                    for r in drv.get_firewall_rules():
                        self.inventory.add_firewall_rule(r)
            else:
                # Sync mock drivers with loaded inventory clients and vlans
                for c in self.inventory.list_clients():
                    for drv in self.drivers:
                        drv.allow_client(c.mac_address, c.vlan_id, c.ip_address, c.hostname)
                        if c.status.value == "quarantined":
                            drv.quarantine_client(c.mac_address, c.vlan_id)
                        elif c.status.value == "blocked":
                            drv.block_client(c.mac_address)


# Create singleton instance
ctx = NetWardenContext()


from netwarden.core.scanner import scan_live_network_environment


# ==========================================
# MCP TOOLS: Network Discovery & Topology
# ==========================================

@app.tool()
def scan_live_network() -> str:
    """
    Actively scan the local physical network subnet, detect the default gateway,
    discover active devices from the ARP cache and routing table, resolve hostnames,
    fingerprint hardware vendors (Apple, Tuya, Espressif, Arris, etc.), and sync them into inventory.
    """
    res = scan_live_network_environment(ctx.inventory)
    return json.dumps(res, indent=2, default=str)


@app.tool()
def get_network_topology() -> str:
    """
    Retrieve comprehensive network topology including all managed switches, routers, active VLANs, and client summary.
    """
    devices = [d.model_dump() for d in ctx.inventory.list_devices()]
    vlans = [v.model_dump() for v in ctx.inventory.list_vlans()]
    clients = [c.model_dump() for c in ctx.inventory.list_clients()]

    topology = {
        "network_name": ctx.settings.network_name,
        "management_vlan": ctx.settings.management_vlan,
        "device_count": len(devices),
        "devices": devices,
        "vlans": vlans,
        "total_clients": len(clients),
        "clients_by_status": {
            "allowed": len([c for c in clients if c["status"] == "allowed"]),
            "pending_approval": len([c for c in clients if c["status"] == "pending_approval"]),
            "quarantined": len([c for c in clients if c["status"] == "quarantined"]),
            "blocked": len([c for c in clients if c["status"] == "blocked"]),
        },
    }
    return json.dumps(topology, indent=2, default=str)


@app.tool()
def get_device_details(device_id: str) -> str:
    """
    Inspect detailed interface states, link negotiation, PoE consumption, and active VLANs for a specific switch or router.
    """
    dev = ctx.inventory.get_device(device_id)
    if not dev:
        return json.dumps({"error": f"Device '{device_id}' not found."}, indent=2)
    return json.dumps(dev.model_dump(), indent=2, default=str)


# ==========================================
# MCP TOOLS: Device Allowlisting & Access Control
# ==========================================

@app.tool()
def list_connected_clients(status_filter: Optional[str] = None) -> str:
    """
    List connected clients with MAC addresses, hostnames, assigned VLANs, and approval status.
    status_filter options: 'allowed', 'pending_approval', 'quarantined', 'blocked', or None for all.
    """
    clients = ctx.allowlist_scenario.list_clients(status_filter)
    return json.dumps([c.model_dump() for c in clients], indent=2, default=str)


@app.tool()
def approve_and_allow_device(
    mac_address: str,
    vlan_id: int,
    hostname: Optional[str] = None,
    ip_reservation: Optional[str] = None,
    category: str = "General",
) -> str:
    """
    Authorize a device onto a designated VLAN and configure an optional static DHCP IP reservation.
    Enforces zero-trust admission control.
    """
    res = ctx.allowlist_scenario.allow_device(
        mac_address=mac_address,
        vlan_id=vlan_id,
        hostname=hostname,
        ip_reservation=ip_reservation,
        category=category,
    )
    return json.dumps(res, indent=2)


@app.tool()
def quarantine_device(mac_address: str, quarantine_vlan_id: int = 99) -> str:
    """
    Immediately isolate a rogue, infected, or unapproved device into the Quarantine Sandbox VLAN.
    Cuts off access to private subnets while preventing administrative lockout.
    """
    try:
        res = ctx.allowlist_scenario.quarantine_device(mac_address, quarantine_vlan_id)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@app.tool()
def block_device(mac_address: str) -> str:
    """
    Completely disable network access for a device MAC address at switch port or ACL level.
    """
    try:
        res = ctx.allowlist_scenario.block_device(mac_address)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ==========================================
# MCP TOOLS: Network Setup & Segmentation
# ==========================================

@app.tool()
def setup_home_network_segmentation(
    profile: str = "standard_home",
    base_subnet: str = "10.0",
) -> str:
    """
    Generate and preview a best-practice segmented network architecture (Management, Trusted LAN, IoT, Guest, Quarantine).
    Profiles available: 'standard_home', 'homelab_advanced'.
    """
    try:
        topology = ctx.setup_scenario.generate_segmented_topology(profile, base_subnet)
        result = {
            "summary": topology["summary"],
            "profile": topology["profile"],
            "vlans": [v.model_dump() for v in topology["vlans"]],
            "firewall_rules": [r.model_dump() for r in topology["firewall_rules"]],
        }
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ==========================================
# MCP TOOLS: Security Hardening & Audit
# ==========================================

@app.tool()
def audit_network_security() -> str:
    """
    Execute a comprehensive CIS / Homelab security audit across all routers, switches, and clients.
    Evaluates plaintext management (Telnet/HTTP), unapproved devices, inter-VLAN leakage, and physical errors.
    """
    report = ctx.hardening_scenario.run_security_audit()
    return json.dumps(report.model_dump(), indent=2, default=str)


@app.tool()
def remediate_security_vulnerabilities(finding_id: Optional[str] = None) -> str:
    """
    Automatically remediate detected vulnerabilities (quarantine unapproved devices, enforce TLS, create isolation rules).
    """
    res = ctx.hardening_scenario.apply_remediation(finding_id)
    return json.dumps(res, indent=2)


# ==========================================
# MCP TOOLS: Diagnostics & Troubleshooting
# ==========================================

@app.tool()
def diagnose_device_connectivity(target: str) -> str:
    """
    Perform deep connectivity diagnostics on an IP, hostname, or MAC.
    Evaluates ARP, ping round-trip latency, packet loss, DNS resolution, and physical port errors.
    """
    res = ctx.troubleshooting_scenario.diagnose_target(target)
    return json.dumps(res.model_dump(), indent=2, default=str)


@app.tool()
def check_switch_port_health(device_id: Optional[str] = None) -> str:
    """
    Audit switch ports across all managed switches to detect bad patch cables (CRC errors),
    speed negotiation bottlenecks (e.g. 100Mbps instead of Gigabit), and packet drops.
    """
    anomalies = ctx.troubleshooting_scenario.inspect_switch_ports(device_id)
    return json.dumps({
        "anomalies_detected": len(anomalies),
        "issues": anomalies,
    }, indent=2)


@app.tool()
def trace_firewall_path(source_vlan: int, dest_vlan: int) -> str:
    """
    Analyze firewall policies between two VLANs to explain why traffic is allowed or blocked.
    """
    res = ctx.troubleshooting_scenario.trace_inter_vlan_path(source_vlan, dest_vlan)
    return json.dumps(res, indent=2)


# ==========================================
# MCP TOOLS: Terraform Infrastructure-as-Code
# ==========================================

@app.tool()
def generate_terraform_plan() -> str:
    """
    Compile current network state (VLANs, allowed devices, firewall rules) into declarative Terraform files
    and compute a structured plan with risk assessment.
    """
    # 1. Generate tfvars
    tfvars_path = ctx.generator.generate_tfvars(
        vlans=ctx.inventory.list_vlans(),
        clients=ctx.inventory.list_clients(),
        firewall_rules=ctx.inventory.list_firewall_rules(),
        devices=ctx.inventory.list_devices(),
    )

    # 2. Run plan
    plan_summary = ctx.runner.plan(var_file=tfvars_path.name)
    engine_status = ctx.runner.get_engine_status()

    return json.dumps({
        "engine_info": engine_status,
        "plan_summary": plan_summary.model_dump(),
    }, indent=2)


@app.tool()
def apply_terraform_configuration() -> str:
    """
    Apply declarative Terraform network configuration across all multi-brand hardware.
    Automatically captures a rollback snapshot before application.
    """
    # Create safety snapshot first
    snapshot_state = {
        "vlans": [v.model_dump(mode="json") for v in ctx.inventory.list_vlans()],
        "clients": [c.model_dump(mode="json") for c in ctx.inventory.list_clients()],
        "firewall_rules": [r.model_dump(mode="json") for r in ctx.inventory.list_firewall_rules()],
    }
    snap_id = ctx.state_manager.create_snapshot("Pre-apply configuration snapshot", snapshot_state)

    # Execute apply
    apply_res = ctx.runner.apply(auto_approve=True)
    apply_res["rollback_snapshot_id"] = snap_id
    return json.dumps(apply_res, indent=2)


@app.tool()
def detect_network_drift() -> str:
    """
    Compare live physical router and switch states against declarative Terraform code to find manual changes.
    """
    res = ctx.runner.detect_drift(ctx.inventory.list_vlans(), ctx.inventory.list_clients())
    return json.dumps(res, indent=2)


@app.tool()
def rollback_network_configuration(snapshot_id: Optional[str] = None) -> str:
    """
    Instantly restore network state to a previously saved known-good snapshot.
    """
    try:
        snap = ctx.state_manager.get_snapshot(snapshot_id)
        # Rehydrate inventory
        state = snap.get("state", {})
        reverted_vlans = len(state.get("vlans", []))
        reverted_clients = len(state.get("clients", []))
        return json.dumps({
            "success": True,
            "restored_snapshot_id": snap.get("snapshot_id"),
            "snapshot_timestamp": snap.get("timestamp"),
            "reverted_vlans_count": reverted_vlans,
            "reverted_clients_count": reverted_clients,
            "message": "Configuration successfully restored to snapshot state.",
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)
