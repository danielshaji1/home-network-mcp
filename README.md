# NetWarden: Multi-Brand Home Network MCP Agent & Terraform Orchestrator

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP 2.x](https://img.shields.io/badge/MCP-2.x%20Compliant-green.svg)](https://modelcontextprotocol.io/)
[![Terraform / OpenTofu](https://img.shields.io/badge/IaC-Terraform%20%7C%20OpenTofu-purple.svg)](https://opentofu.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**NetWarden** is an intelligent Model Context Protocol (MCP) server and AI agent that seamlessly integrates into heterogeneous home and homelab networks. It allows AI models (such as Claude Desktop, Cursor, Antigravity, and Open-WebUI) to discover, configure, harden, and troubleshoot routers, managed switches, access points, and client devices across multiple brands—all backed by declarative **Terraform / OpenTofu** Infrastructure-as-Code.

---

## 🌟 Key Capabilities

* **Multi-Brand Hardware Support**: Uniform driver abstraction across **Ubiquiti UniFi**, **MikroTik RouterOS**, **OPNsense / pfSense**, **OpenWrt**, **Cisco Catalyst / CBS**, and **Pi-hole**.
* **Zero-Hardware Simulation Mode**: Built-in mock driver for immediate sandbox testing, CI/CD verification, and offline development without needing physical hardware attached.
* **Declarative Infrastructure as Code (Terraform)**:
  * Generates structured HCL and `network.tfvars.json` from high-level network topology.
  * Native execution via `terraform` or `tofu` CLI, with built-in high-fidelity fallback simulation.
  * Real-time **Drift Detection** between live hardware state and declarative code.
* **Safety Guardrails & Lockout Prevention**:
  * Prevents accidental disconnection by safeguarding administrative MACs, gateway IPs, and the primary management plane.
  * Pre-execution risk assessment scoring (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  * Automatic versioned state snapshots before applies with instant **One-Click Rollback**.
* **Dedicated Scenario Engines**:
  * **Setup & Segmentation**: Automated subnet allocation and zero-trust VLAN boundary rules (Management, Trusted LAN, IoT, Guest, Quarantine).
  * **Zero-Trust Device Allowlisting**: MAC-based admission control, static DHCP reservations, and automated containment for rogue devices.
  * **Security Hardening**: CIS and Homelab security audit engine with automated one-click remediation.
  * **Diagnostics & Troubleshooting**: Automated Layer 1 through Layer 7 triage (physical cable CRC error detection, link speed bottleneck diagnosis, latency, and firewall path evaluations).

---

## 🏗️ Architecture Overview

```mermaid
graph TD
    User([User / AI Assistant]) -->|MCP Protocol / stdio / SSE| Server[NetWarden MCP Server]
    Server --> Safety[Safety Guardrails & Lockout Prevention]
    Safety --> Scenarios[Scenario Engines: Setup | Hardening | Allowlist | Diagnostics]
    Scenarios --> IaC[Terraform / OpenTofu Orchestrator]
    Scenarios --> Drivers[Multi-Brand Drivers Engine]
    
    Drivers --> UniFi[Ubiquiti UniFi Controller]
    Drivers --> MikroTik[MikroTik RouterOS v7]
    Drivers --> OPNsense[OPNsense / pfSense]
    Drivers --> OpenWrt[OpenWrt ubus / LuCI]
    Drivers --> Cisco[Cisco Managed Switches]
    Drivers --> Pihole[Pi-hole DNS Sinkhole]
    Drivers --> Mock[Simulated Network Lab]

    IaC --> StateManager[State Snapshots & Instant Rollback]
```

---

## 🚀 Quickstart & Installation

### Prerequisites
* Python 3.10+
* Git
* *(Optional)* Terraform or OpenTofu CLI installed (`brew install opentofu` or `brew install hashicorp/tap/terraform`). If neither is installed, NetWarden operates in high-fidelity declarative simulation mode automatically.

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/danielshaji1/home-network-mcp.git
cd home-network-mcp

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies and netwarden package
pip install -e ".[dev]"
```

### 2. Verify with the Test Suite

```bash
pytest -v tests
```
*All 28 unit and integration tests will run and pass in under a second.*

---

## 🔌 Connecting to MCP Clients

### 1. Claude Desktop
Add the following to your Claude Desktop configuration file:
* **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "netwarden": {
      "command": "/Users/danielshaji/home-network-mcp/.venv/bin/python",
      "args": ["/Users/danielshaji/home-network-mcp/mcp_server.py"]
    }
  }
}
```

### 2. Cursor IDE
In Cursor **Settings > Features > MCP**, click **Add New MCP Server**:
* **Name**: `netwarden`
* **Type**: `command`
* **Command**: `/Users/danielshaji/home-network-mcp/.venv/bin/python /Users/danielshaji/home-network-mcp/mcp_server.py`

### 3. Remote / Web Agents (SSE Transport)
To run NetWarden as a network service over Server-Sent Events (SSE):
```bash
python mcp_server.py --transport sse --host 0.0.0.0 --port 8000
```

---

## 🛠️ MCP Tools Reference

NetWarden registers 16 specialized tools with full Pydantic type inference and docstrings:

| Tool Category | Tool Name | Description |
|---|---|---|
| **Topology & Discovery** | `get_network_topology()` | Returns all switches, routers, VLAN segments, and client breakdown. |
| | `get_device_details(device_id)` | Deep inspection of port link speeds, PoE consumption, and active VLANs. |
| **Device Access Control** | `list_connected_clients(status_filter)` | Lists clients (`allowed`, `pending_approval`, `quarantined`, `blocked`). |
| | `approve_and_allow_device(mac, vlan, ...)` | Authorizes device on a VLAN with optional static DHCP reservation. |
| | `quarantine_device(mac, vlan_id=99)` | Isolates rogue or suspicious device into Quarantine Sandbox. |
| | `block_device(mac)` | Disables switch port or drops client traffic at firewall level. |
| **Network Setup** | `setup_home_network_segmentation(profile)` | Generates hardened VLANs and boundary firewall policies. |
| **Security Hardening** | `audit_network_security()` | Performs CIS/Homelab security audit and calculates health score (0-100). |
| | `remediate_security_vulnerabilities()` | Automatically applies fixes for unapproved devices, TLS, and isolation. |
| **Diagnostics** | `diagnose_device_connectivity(target)` | Multi-stage Layer 1-7 triage (ping, latency, loss, DNS, port errors). |
| | `check_switch_port_health(device_id)` | Scans switch ports for bad patch cables (CRC errors) and 100M bottlenecks. |
| | `trace_firewall_path(source_vlan, dest_vlan)` | Analyzes rules to explain why inter-VLAN traffic is permitted or dropped. |
| **Terraform IaC** | `generate_terraform_plan()` | Compiles declarative manifests and computes plan with risk analysis. |
| | `apply_terraform_configuration()` | Applies declarative configuration with pre-apply rollback snapshots. |
| | `detect_network_drift()` | Catches out-of-band changes between live devices and Terraform state. |
| | `rollback_network_configuration(snap_id)` | Instantly restores network state to previous snapshot. |

---

## 💻 Terminal CLI Utility

NetWarden includes a rich terminal CLI for direct command-line operations:

```bash
# View network topology and VLAN segments
netwarden topology

# List connected clients
netwarden clients

# Authorize a new device on IoT VLAN 30 with static DHCP IP
netwarden allow aa:bb:cc:dd:ee:ff 30 --name "Smart-Sensor" --ip 10.0.30.70 --category IoT

# Quarantine a rogue device into Quarantine Sandbox VLAN 99
netwarden quarantine aa:bb:cc:dd:ee:ff

# Run security hardening audit
netwarden audit

# Troubleshoot a degraded camera or host
netwarden diagnose Hikvision-Camera

# Preview declarative Terraform plan
netwarden plan

# Apply Terraform configuration with safety snapshot
netwarden apply
```

---

## 🔒 Safety Guardrails & Lockout Protection

Configuring routers and switches via AI automation requires fail-safe guardrails. NetWarden protects you by:
1. **Never blocking admin devices**: MAC addresses and IPs specified in `protected_macs` or `protected_ips` can never be dropped or quarantined.
2. **Management Plane Invariant**: Rules that would sever connectivity to the management interface are rejected before execution.
3. **Subnet Conflict Prevention**: VLAN subnet allocations are mathematically verified against CIDR overlaps.
4. **Pre-Apply Snapshots**: Every apply creates a versioned snapshot in `terraform/backups/`, enabling instant rollback with `rollback_network_configuration()`.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.
