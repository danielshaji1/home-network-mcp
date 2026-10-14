# NetWarden Architecture & Technical Specification

NetWarden is an intelligent, multi-brand network orchestration agent exposed via the **Model Context Protocol (MCP)**. It combines declarative **Infrastructure-as-Code (Terraform)** with proactive AI operations for heterogeneous home and homelab networks.

---

## High-Level Architecture

```mermaid
graph TD
    subgraph "AI Agent & Client Layer"
        LLM[Claude / Cursor / Antigravity / Open-WebUI]
        CLI[NetWarden Terminal CLI]
    end

    subgraph "NetWarden MCP Server"
        MCPEngine[MCP Protocol Interface (MCPServer 2.x)]
        Safety[Safety Guardrails & Lockout Prevention]
        Inv[(Unified State Database & Inventory)]
    end

    subgraph "Scenario Engines"
        Setup[Setup & Segmentation]
        Hardening[Security Hardening & CIS Audit]
        Allowlist[Device Allowlist & Zero-Trust]
        Troubleshoot[Diagnostics & Layer 1-7 Triage]
    end

    subgraph "Infrastructure-as-Code Engine"
        Generator[Terraform HCL & tfvars Generator]
        Runner[Terraform / OpenTofu Runner]
        StateManager[State Snapshots & Instant Rollback]
    end

    subgraph "Multi-Brand Device Abstraction Layer"
        D_UniFi[Ubiquiti UniFi Driver]
        D_MikroTik[MikroTik RouterOS Driver]
        D_OPNsense[OPNsense / pfSense Driver]
        D_OpenWrt[OpenWrt ubus Driver]
        D_Cisco[Cisco Catalyst/CBS Driver]
        D_Pihole[Pi-hole DNS Driver]
        D_Mock[Simulated Multi-Brand Lab]
    end

    subgraph "Physical Hardware Layer"
        HW_Switch[UniFi / Cisco Switch]
        HW_Router[MikroTik / OpenWrt Router]
        HW_FW[OPNsense Appliance]
        HW_DNS[Pi-hole / AdGuard Server]
    end

    LLM --> MCPEngine
    CLI --> MCPEngine
    MCPEngine --> Safety
    MCPEngine --> Inv
    Safety --> Setup
    Safety --> Hardening
    Safety --> Allowlist
    Safety --> Troubleshoot

    MCPEngine --> Generator
    Generator --> Runner
    Runner --> StateManager

    Setup --> D_UniFi & D_MikroTik & D_OPNsense & D_OpenWrt & D_Cisco & D_Pihole & D_Mock
    Allowlist --> D_UniFi & D_MikroTik & D_OPNsense & D_OpenWrt & D_Cisco & D_Pihole & D_Mock
    Troubleshoot --> D_UniFi & D_MikroTik & D_OPNsense & D_OpenWrt & D_Cisco & D_Pihole & D_Mock
    Hardening --> D_UniFi & D_MikroTik & D_OPNsense & D_OpenWrt & D_Cisco & D_Pihole & D_Mock

    D_UniFi --> HW_Switch
    D_MikroTik --> HW_Router
    D_OPNsense --> HW_FW
    D_Pihole --> HW_DNS
```

---

## Core Components

### 1. Safety Guardrails & Lockout Prevention Engine (`netwarden.core.safety`)
Operating network hardware programmatically carries risk of administrative lockout (e.g., dropping SSH ports, deleting the management VLAN, or quarantining the operator's laptop).
NetWarden implements strict safety invariants:
* **Administrative Device Protection**: Dedicated MAC addresses and IP addresses cannot be blocked, quarantined, or isolated.
* **Management Plane Invariant**: Designated Management VLAN (default `1`) cannot be removed or have default drop rules applied without explicit source constraints.
* **Subnet Collision Detection**: All proposed VLAN subnets are mathematically validated against existing IPv4 address allocations using `ipaddress` network overlap algorithms.
* **Risk Categorization**: Every operation is analyzed and assigned a risk score (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

### 2. Multi-Brand Driver Abstraction Layer (`netwarden.drivers`)
Each vendor hardware platform implements the `BaseDeviceDriver` abstract interface:
| Brand | Supported Protocols | Key Functions |
|---|---|---|
| **Ubiquiti UniFi** | UniFi OS REST API (`/proxy/network/api/s/...`) | Switch port profiles, VLAN creation, client blocking, Wi-Fi SSIDs |
| **MikroTik RouterOS** | RouterOS v7 REST API (`/rest/...`) | Bridge VLAN filtering, IP addresses, firewall filter/NAT, DHCP leases |
| **OPNsense / pfSense** | OPNsense Core REST API (Key/Secret) | Inter-VLAN firewall filter rules, network aliases, DHCP static bindings |
| **OpenWrt** | LuCI JSON-RPC / ubus / UCI | Bridge VLANs, wireless SSIDs, firewall3/firewall4 nftables |
| **Cisco** | Catalyst / CBS / SG-series CLI & NETCONF | Port security (sticky MAC), 802.1Q trunks, access VLAN assignments |
| **Pi-hole** | FTL DNS API | Local DNS records, static DHCP leases, domain blocking groups |
| **Mock Simulator** | Pure Python In-Memory | High-fidelity multi-brand simulation for testing and CI validation |

### 3. Declarative Terraform Engine (`netwarden.terraform`)
* **Generator (`generator.py`)**: Translates high-level inventory intent into structured `network.tfvars.json` and human-readable HCL snippets.
* **Runner (`runner.py`)**: Automatically detects installed `terraform` or `tofu` binaries. If no binary is installed on the host, gracefully operates in a declarative simulation mode.
* **State Manager (`state_manager.py`)**: Prior to executing any Terraform apply or live hardware mutation, captures an atomic JSON snapshot in `terraform/backups/snap_<timestamp>.json`. If an anomaly is detected, `rollback_network_configuration()` reverts the state instantly.
* **Drift Detection**: Compares declarative tfvars against live inventory to identify unauthorized out-of-band changes.

### 4. Specialized Scenario Engines (`netwarden.scenarios`)
1. **Network Setup & Segmentation (`setup.py`)**:
   Generates non-overlapping subnets (Management, Trusted LAN, IoT, Guest, Quarantine) and enforces zero-trust boundaries (IoT isolated to WAN only, Guest isolated from all private subnets).
2. **Security Hardening & CIS Audit (`hardening.py`)**:
   Scans management planes, Layer 2 protections (DHCP Snooping, Port Security), unapproved devices, and generates an automated remediation plan.
3. **Device Allowlisting & Access Control (`allowlist.py`)**:
   Implements zero-trust MAC admission control. Unknown devices are directed to Quarantine Sandbox VLAN 99 until authorized.
4. **Diagnostics & Troubleshooting (`troubleshooting.py`)**:
   Deep multi-layer triage (Physical cable CRC checks, link negotiation bottlenecks, gateway latency, packet loss, DNS resolution, and firewall path evaluations).
