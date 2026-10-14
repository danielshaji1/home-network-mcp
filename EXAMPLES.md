# NetWarden Practical Usage Examples & Scenarios

This document illustrates how AI assistants (via Model Context Protocol) and human operators interact with NetWarden across common network scenarios.

---

## Scenario 1: Greenfield Network Setup & Segmentation

### User Prompt:
> *"I just bought a UniFi 24-port switch and a MikroTik router. Can you design a secure VLAN structure for my home, separate my IoT devices, and generate the Terraform code?"*

### MCP Tool Sequence:
1. Call `setup_home_network_segmentation(profile="standard_home", base_subnet="10.0")`
   * Creates VLAN 1 (Management: `10.0.1.0/24`)
   * Creates VLAN 10 (Trusted LAN: `10.0.10.0/24`)
   * Creates VLAN 30 (IoT Smart Home: `10.0.30.0/24`)
   * Creates VLAN 50 (Guest Network: `10.0.50.0/24`)
   * Creates VLAN 99 (Quarantine Sandbox: `10.0.99.0/24`)
   * Adds firewall isolation rules blocking VLAN 30 from VLAN 10 and blocking VLAN 30 from hitting Router Admin Port 80/443.
2. Call `generate_terraform_plan()`
   * Generates `network.tfvars.json`
   * Computes declarative resource diff (+12 resources)
3. Call `apply_terraform_configuration()`
   * Creates pre-apply state snapshot (`snap_...`)
   * Reconciles configuration across UniFi and MikroTik hardware.

---

## Scenario 2: Zero-Trust Device Allowlisting & Rogue Containment

### User Prompt:
> *"There is an unknown device on my network. What is it, and can you isolate it until I can verify what it is?"*

### MCP Tool Sequence:
1. Call `list_connected_clients(status_filter="pending_approval")`
   ```json
   [
     {
       "mac_address": "aa:bb:cc:dd:ee:ff",
       "hostname": "unknown-rogue-device",
       "ip_address": "10.0.1.199",
       "vlan_id": 1,
       "status": "pending_approval",
       "switch_port": 5
     }
   ]
   ```
2. Call `quarantine_device(mac_address="aa:bb:cc:dd:ee:ff", quarantine_vlan_id=99)`
   * Switches Switch Port 5 PVID to VLAN 99.
   * Completely cuts off internal LAN and Internet WAN access.
3. *Later, when verified as a smart thermostat:*
   Call `approve_and_allow_device(mac_address="aa:bb:cc:dd:ee:ff", vlan_id=30, hostname="LivingRoom-Thermostat", ip_reservation="10.0.30.75", category="IoT")`
   * Migrates device to IoT VLAN 30.
   * Creates static DHCP lease and local DNS record.

---

## Scenario 3: Security Hardening & CIS Compliance Audit

### User Prompt:
> *"Run a security audit on my network switches and routers, tell me where my vulnerabilities are, and fix what you can automatically."*

### MCP Tool Sequence:
1. Call `audit_network_security()`
   * Returns security score: `7 / 100` (CRITICAL)
   * Detects plaintext HTTP interface on switch port 80.
   * Detects unapproved device on Management VLAN.
   * Detects missing firewall boundary between IoT and Workstations.
2. Call `remediate_security_vulnerabilities()`
   * Automatically creates IoT-to-LAN drop rule.
   * Quarantines rogue device into VLAN 99.
   * Enforces TLS-only management listeners.
   * Re-evaluates audit score: improves from `7` to `88 / 100` (LOW RISK).

---

## Scenario 4: Troubleshooting Cable Degradation & Performance Bottlenecks

### User Prompt:
> *"My living room security camera stream keeps stuttering and dropping packets. Can you diagnose what is wrong?"*

### MCP Tool Sequence:
1. Call `diagnose_device_connectivity(target="Hikvision-Camera")`
   * Ping round-trip latency: 18.4 ms
   * Packet loss: 12.5%
   * Switch port CRC frame errors: 142
   * Root cause: Packet loss directly correlated with CRC frame alignment errors on Switch Port 3.
2. Call `check_switch_port_health()`
   * Flags Port 3: Excessive CRC errors and link speed negotiation downgraded to 100 Mbps instead of 1000 Mbps.
   * Actionable Advice: *"Replace the physical RJ-45 patch cable on Switch Port 3 and check for damaged pins."*

---

## Scenario 5: Declarative Terraform Plan & Drift Detection

### User Prompt:
> *"Did anyone manually change any VLANs or rules on the switches without updating our Terraform code?"*

### MCP Tool Sequence:
1. Call `detect_network_drift()`
   * Analyzes live switch CAM and VLAN tables vs `network.tfvars.json`.
   * Flags any unmanaged clients or out-of-band VLAN additions.
2. Call `generate_terraform_plan()`
   * Refreshes declarative manifests to restore alignment.
