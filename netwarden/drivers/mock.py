"""
NetWarden Simulated / Mock Multi-Brand Network Driver.
High-fidelity simulated environment for zero-hardware lab testing, validation, and automated tests.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from netwarden.drivers.base import BaseDeviceDriver
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
    HardeningFinding,
    SeverityLevel,
    DiagnosticResult,
)


class MockDeviceDriver(BaseDeviceDriver):
    """Simulates realistic multi-brand router/switch behaviour with internal state tracking."""

    def __init__(
        self,
        device_id: str,
        name: str,
        ip: str,
        vendor: VendorType = VendorType.UNIFI,
        device_type: DeviceType = DeviceType.SWITCH,
        model: str = "USW-Pro-24-PoE",
        firmware: str = "6.5.59",
        **kwargs,
    ):
        super().__init__(device_id, name, ip, **kwargs)
        self.vendor = vendor
        self.device_type = device_type
        self.model = model
        self.firmware = firmware

        # Initialize mock ports
        self.ports: Dict[int, PortInfo] = {}
        port_count = 24 if "24" in model else (8 if "8" in model else 16)
        for p in range(1, port_count + 1):
            is_uplink = p in [port_count, port_count - 1]
            self.ports[p] = PortInfo(
                port_number=p,
                name=f"Port {p}" + (" (Uplink)" if is_uplink else ""),
                enabled=True,
                link_up=p in [1, 2, 3, 4, port_count],
                speed_mbps=1000 if not (p == 3) else 100,  # simulate one 100M bottleneck
                mode=PortMode.TRUNK if is_uplink else PortMode.ACCESS,
                pvid=1,
                allowed_vlans=[1, 10, 20, 30, 50, 99] if is_uplink else [1],
                poe_enabled=p <= 8,
                poe_power_watts=8.4 if p in [1, 2] else 0.0,
                connected_mac=f"00:11:22:33:44:{p:02x}" if p in [1, 2, 3, 4] else None,
                crc_errors=142 if p == 3 else 0,  # simulate bad cable on port 3
            )

        # Initialize mock VLANs
        self.vlans: Dict[int, VLANDefinition] = {
            1: VLANDefinition(
                vlan_id=1,
                name="Default_Management",
                subnet_cidr="10.0.1.0/24",
                gateway_ip="10.0.1.1",
                dhcp_start="10.0.1.50",
                dhcp_end="10.0.1.200",
                purpose=VLANPurpose.MANAGEMENT,
                isolation_level=IsolationLevel.ROUTED,
                description="Network equipment management VLAN",
            ),
            10: VLANDefinition(
                vlan_id=10,
                name="Trusted_LAN",
                subnet_cidr="10.0.10.0/24",
                gateway_ip="10.0.10.1",
                dhcp_start="10.0.10.100",
                dhcp_end="10.0.10.250",
                purpose=VLANPurpose.TRUSTED_LAN,
                isolation_level=IsolationLevel.ROUTED,
                description="Trusted workstations, laptops, and phones",
            ),
            30: VLANDefinition(
                vlan_id=30,
                name="IoT_SmartHome",
                subnet_cidr="10.0.30.0/24",
                gateway_ip="10.0.30.1",
                dhcp_start="10.0.30.50",
                dhcp_end="10.0.30.200",
                purpose=VLANPurpose.IOT,
                isolation_level=IsolationLevel.INTERNET_ONLY,
                description="Smart cameras, sensors, and bulbs",
            ),
            50: VLANDefinition(
                vlan_id=50,
                name="Guest_Network",
                subnet_cidr="10.0.50.0/24",
                gateway_ip="10.0.50.1",
                dhcp_start="10.0.50.50",
                dhcp_end="10.0.50.250",
                purpose=VLANPurpose.GUEST,
                isolation_level=IsolationLevel.INTERNET_ONLY,
                description="Isolated visitors network",
            ),
            99: VLANDefinition(
                vlan_id=99,
                name="Quarantine_Jail",
                subnet_cidr="10.0.99.0/24",
                gateway_ip="10.0.99.1",
                dhcp_start="10.0.99.50",
                dhcp_end="10.0.99.99",
                purpose=VLANPurpose.QUARANTINE,
                isolation_level=IsolationLevel.ISOLATED,
                description="Sandbox for unauthorized or suspicious devices",
            ),
        }

        # Initialize mock clients
        self.clients: Dict[str, ConnectedClient] = {
            "00:11:22:33:44:01": ConnectedClient(
                mac_address="00:11:22:33:44:01",
                ip_address="10.0.10.105",
                hostname="Daniels-MacBook-Pro",
                vendor_oui="Apple, Inc.",
                vlan_id=10,
                device_category="Workstation",
                status=ClientStatus.ALLOWED,
                switch_id=self.device_id,
                switch_port=1,
                dhcp_reservation=True,
                notes="Primary Admin Station",
            ),
            "00:11:22:33:44:02": ConnectedClient(
                mac_address="00:11:22:33:44:02",
                ip_address="10.0.30.55",
                hostname="Tuya-Smart-Plug",
                vendor_oui="Espressif Inc.",
                vlan_id=30,
                device_category="IoT",
                status=ClientStatus.ALLOWED,
                switch_id=self.device_id,
                switch_port=2,
                dhcp_reservation=False,
                notes="Smart Plug Living Room",
            ),
            "00:11:22:33:44:03": ConnectedClient(
                mac_address="00:11:22:33:44:03",
                ip_address="10.0.30.60",
                hostname="Hikvision-Camera",
                vendor_oui="Hangzhou Hikvision",
                vlan_id=30,
                device_category="IoT",
                status=ClientStatus.ALLOWED,
                switch_id=self.device_id,
                switch_port=3,
                dhcp_reservation=True,
                notes="Front Door IP Camera (High CRC errors detected)",
            ),
            "b8:27:eb:aa:bb:cc": ConnectedClient(
                mac_address="b8:27:eb:aa:bb:cc",
                ip_address="10.0.1.15",
                hostname="pi-hole-dns",
                vendor_oui="Raspberry Pi Trading",
                vlan_id=1,
                device_category="Server",
                status=ClientStatus.ALLOWED,
                switch_id=self.device_id,
                switch_port=4,
                dhcp_reservation=True,
                notes="Primary Homelab DNS Sinkhole",
            ),
            "aa:bb:cc:dd:ee:ff": ConnectedClient(
                mac_address="aa:bb:cc:dd:ee:ff",
                ip_address="10.0.1.199",
                hostname="unknown-rogue-device",
                vendor_oui="Unknown OUI",
                vlan_id=1,
                device_category="Unknown",
                status=ClientStatus.PENDING_APPROVAL,
                switch_id=self.device_id,
                switch_port=5,
                dhcp_reservation=False,
                notes="Newly detected unauthorized device on Management subnet!",
            ),
        }

        # Initialize mock firewall rules
        self.firewall_rules: Dict[str, FirewallRule] = {
            "rule-100": FirewallRule(
                id="rule-100",
                name="Allow Established and Related",
                action=RuleAction.ACCEPT,
                direction=RuleDirection.FORWARD,
                protocol="any",
                enabled=True,
                comment="Stateful return traffic allow",
            ),
            "rule-200": FirewallRule(
                id="rule-200",
                name="Isolate IoT from Private LANs",
                action=RuleAction.DROP,
                direction=RuleDirection.FORWARD,
                source_vlan=30,
                dest_vlan=10,
                protocol="any",
                enabled=True,
                comment="Block IoT smart devices from accessing workstations and file servers",
            ),
            "rule-300": FirewallRule(
                id="rule-300",
                name="Block IoT Access to Management Web UI",
                action=RuleAction.DROP,
                direction=RuleDirection.FORWARD,
                source_vlan=30,
                dest_vlan=1,
                protocol="tcp",
                dest_ports=[80, 443, 8443, 22],
                enabled=True,
                comment="Prevent compromised IoT gear from hitting switch/router management ports",
            ),
        }

    def connect(self) -> bool:
        self._connected = True
        return True

    def disconnect(self) -> None:
        self._connected = False

    def test_connection(self) -> bool:
        return True

    def get_device_info(self) -> NetworkDevice:
        return NetworkDevice(
            id=self.device_id,
            name=self.name,
            vendor=self.vendor,
            device_type=self.device_type,
            ip_address=self.ip,
            mac_address=f"fc:ec:da:{self.device_id[:2]}:01:02",
            model=self.model,
            firmware_version=self.firmware,
            status=DeviceStatus.ONLINE,
            uptime_seconds=345600,
            ports=list(self.ports.values()),
            active_vlans=list(self.vlans.keys()),
            management_ip=self.ip,
            metadata={"location": "Living Room Rack", "rack_unit": "U2"},
        )

    def get_ports(self) -> List[PortInfo]:
        return list(self.ports.values())

    def set_port_vlan(
        self, port_number: int, vlan_id: int, mode: PortMode = PortMode.ACCESS
    ) -> bool:
        if port_number not in self.ports:
            return False
        port = self.ports[port_number]
        port.pvid = vlan_id
        port.mode = mode
        if mode == PortMode.ACCESS:
            port.allowed_vlans = [vlan_id]
        elif vlan_id not in port.allowed_vlans:
            port.allowed_vlans.append(vlan_id)
        return True

    def get_vlans(self) -> List[VLANDefinition]:
        return list(self.vlans.values())

    def apply_vlan(self, vlan: VLANDefinition) -> bool:
        self.vlans[vlan.vlan_id] = vlan
        return True

    def get_clients(self) -> List[ConnectedClient]:
        return list(self.clients.values())

    def allow_client(
        self, mac: str, vlan_id: int, ip: Optional[str] = None, hostname: Optional[str] = None
    ) -> bool:
        mac_key = mac.lower()
        if mac_key in self.clients:
            client = self.clients[mac_key]
            client.status = ClientStatus.ALLOWED
            client.vlan_id = vlan_id
            if ip:
                client.ip_address = ip
                client.dhcp_reservation = True
            if hostname:
                client.hostname = hostname
            client.last_seen = datetime.now(timezone.utc)
            return True
        else:
            self.clients[mac_key] = ConnectedClient(
                mac_address=mac_key,
                ip_address=ip or f"10.0.{vlan_id}.150",
                hostname=hostname or f"device-{mac_key.replace(':', '')[-4:]}",
                vlan_id=vlan_id,
                status=ClientStatus.ALLOWED,
                dhcp_reservation=bool(ip),
                switch_id=self.device_id,
            )
            return True

    def quarantine_client(self, mac: str, quarantine_vlan_id: int = 99) -> bool:
        mac_key = mac.lower()
        if mac_key in self.clients:
            client = self.clients[mac_key]
            client.status = ClientStatus.QUARANTINED
            client.vlan_id = quarantine_vlan_id
            client.ip_address = f"10.0.{quarantine_vlan_id}.90"
            # If client is bound to a switch port, change port VLAN to quarantine
            if client.switch_port and client.switch_port in self.ports:
                self.set_port_vlan(client.switch_port, quarantine_vlan_id, PortMode.ACCESS)
            return True
        return False

    def block_client(self, mac: str) -> bool:
        mac_key = mac.lower()
        if mac_key in self.clients:
            client = self.clients[mac_key]
            client.status = ClientStatus.BLOCKED
            if client.switch_port and client.switch_port in self.ports:
                self.ports[client.switch_port].enabled = False
            return True
        return False

    def get_firewall_rules(self) -> List[FirewallRule]:
        return list(self.firewall_rules.values())

    def apply_firewall_rule(self, rule: FirewallRule) -> bool:
        self.firewall_rules[rule.id] = rule
        return True

    def audit_security(self) -> List[HardeningFinding]:
        findings = []
        # Check unapproved clients
        for c in self.clients.values():
            if c.status == ClientStatus.PENDING_APPROVAL:
                findings.append(
                    HardeningFinding(
                        id=f"audit-unauth-{c.mac_address}",
                        severity=SeverityLevel.HIGH,
                        category="Access Control",
                        title=f"Unauthorized Device Detected: {c.hostname or c.mac_address}",
                        affected_device_id=self.device_id,
                        affected_device_name=self.name,
                        description=f"Device {c.mac_address} ({c.vendor_oui}) is connected on Management VLAN {c.vlan_id} without allowlist approval.",
                        risk="An unverified device could sniff management traffic or attempt rogue DHCP spoofing.",
                        remediation_suggestion=f"Quarantine device '{c.mac_address}' or move to Guest/IoT VLAN with allowlisting.",
                        auto_remediable=True,
                    )
                )

        # Check default HTTP management
        findings.append(
            HardeningFinding(
                id=f"audit-insecure-mgmt-{self.device_id}",
                severity=SeverityLevel.MEDIUM,
                category="Management Plane",
                title="HTTP Management Interface Enabled",
                affected_device_id=self.device_id,
                affected_device_name=self.name,
                description=f"Switch '{self.name}' has plaintext HTTP/Telnet listener active on port 80.",
                risk="Credentials could be intercepted by local network eavesdropping.",
                remediation_suggestion="Enforce HTTPS-only, redirect HTTP to port 443, and disable Telnet.",
                auto_remediable=True,
            )
        )

        # Check port error counters (e.g. port 3 CRC errors)
        for p in self.ports.values():
            if p.crc_errors > 50:
                findings.append(
                    HardeningFinding(
                        id=f"audit-phy-crc-p{p.port_number}",
                        severity=SeverityLevel.LOW,
                        category="Physical Layer",
                        title=f"Excessive CRC Frame Errors on Port {p.port_number}",
                        affected_device_id=self.device_id,
                        affected_device_name=self.name,
                        description=f"Port {p.port_number} accumulated {p.crc_errors} CRC alignment errors.",
                        risk="Degraded throughput, dropped packets, and periodic link renegotiation.",
                        remediation_suggestion="Inspect physical patch cable, check for electromagnetic interference, or replace termination.",
                        auto_remediable=False,
                    )
                )

        return findings

    def run_diagnostics(self, target: str) -> DiagnosticResult:
        # Check if target matches one of our clients or an IP
        if target == "10.0.30.60" or "Hikvision" in target:
            # Simulate degraded link due to CRC errors
            return DiagnosticResult(
                target=target,
                reachable=True,
                latency_ms=18.4,
                packet_loss_pct=12.5,
                dns_resolves=True,
                resolved_ip="10.0.30.60",
                gateway_reachable=True,
                hop_count=1,
                port_checks={80: True, 554: True},
                switch_port_errors=142,
                root_cause="High packet loss (12.5%) correlated with 142 CRC errors on Switch Port 3 (Hikvision-Camera).",
                recommended_action="Replace physical Ethernet patch cable on Switch Port 3 and verify 1000Mbps link negotiation.",
            )
        elif target == "google.com" or target == "1.1.1.1":
            return DiagnosticResult(
                target=target,
                reachable=True,
                latency_ms=4.2,
                packet_loss_pct=0.0,
                dns_resolves=True,
                resolved_ip="142.250.190.46",
                gateway_reachable=True,
                hop_count=9,
                port_checks={53: True, 443: True},
                root_cause="None detected",
                recommended_action="Network path to WAN and Internet DNS is operating nominally.",
            )
        else:
            return DiagnosticResult(
                target=target,
                reachable=True,
                latency_ms=2.1,
                packet_loss_pct=0.0,
                dns_resolves=True,
                resolved_ip=target,
                gateway_reachable=True,
                hop_count=1,
                port_checks={80: True, 443: True},
                root_cause="None detected",
                recommended_action="Host is reachable with sub-5ms latency.",
            )
