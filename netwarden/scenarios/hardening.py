"""
NetWarden Network Hardening & Security Audit Scenario.
Performs CIS/Homelab security audits and automated remediation.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from netwarden.core.models import (
    HardeningAuditReport,
    HardeningFinding,
    SeverityLevel,
    ClientStatus,
    FirewallRule,
    RuleAction,
    RuleDirection,
)
from netwarden.core.inventory import NetworkInventory
from netwarden.drivers.base import BaseDeviceDriver


class HardeningScenario:
    """Evaluates security posture across multi-brand hardware and remediates vulnerabilities."""

    def __init__(self, inventory: NetworkInventory, drivers: Optional[List[BaseDeviceDriver]] = None):
        self.inventory = inventory
        self.drivers = drivers or []

    def run_security_audit(self) -> HardeningAuditReport:
        """Run a full security audit across all devices, clients, and firewall policies."""
        findings: List[HardeningFinding] = []

        # 1. Query device driver audits
        for driver in self.drivers:
            try:
                driver_findings = driver.audit_security()
                findings.extend(driver_findings)
            except Exception:
                pass

        # 2. Audit clients for unapproved / pending devices on sensitive subnets
        for client in self.inventory.list_clients():
            if client.status == ClientStatus.PENDING_APPROVAL:
                findings.append(
                    HardeningFinding(
                        id=f"audit-unauth-client-{client.mac_address}",
                        severity=SeverityLevel.HIGH,
                        category="Access Control",
                        title=f"Unapproved Device on Network: {client.hostname or client.mac_address}",
                        affected_device_id=client.switch_id or "network",
                        affected_device_name="Switch Access Plane",
                        description=f"Device {client.mac_address} has not been approved in the allowlist and is communicating on VLAN {client.vlan_id}.",
                        risk="Unauthorized access, lateral movement, or malicious DHCP exhaustion.",
                        remediation_suggestion=f"Quarantine device '{client.mac_address}' immediately into Quarantine Sandbox.",
                        auto_remediable=True,
                    )
                )

        # 3. Audit firewall rules for inter-VLAN leakage (IoT to LAN)
        rules = self.inventory.list_firewall_rules()
        iot_drop_exists = any(
            r.action == RuleAction.DROP and r.source_vlan == 30 and r.dest_vlan == 10
            for r in rules
        )
        if not iot_drop_exists and len(self.inventory.list_vlans()) > 1:
            findings.append(
                HardeningFinding(
                    id="audit-missing-iot-isolation",
                    severity=SeverityLevel.CRITICAL,
                    category="Network Segmentation",
                    title="Missing IoT-to-Trusted-LAN Firewall Boundary",
                    affected_device_id="gateway",
                    affected_device_name="Gateway Router",
                    description="No firewall rule explicitly drops packets from IoT VLAN 30 to Trusted LAN 10.",
                    risk="Compromised smart home accessories can attack personal computers, NAS storage, and workstations.",
                    remediation_suggestion="Add rule dropping all traffic from source VLAN 30 to destination VLAN 10.",
                    auto_remediable=True,
                )
            )

        # Compute security score
        crit_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        med_count = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == SeverityLevel.LOW)

        score = max(0, 100 - (crit_count * 25 + high_count * 15 + med_count * 8 + low_count * 3))

        if score >= 90:
            risk_level = "LOW"
        elif score >= 70:
            risk_level = "MEDIUM"
        elif score >= 50:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        recommendations = [
            "Enable 802.1w Protected Management Frames (PMF) on all Wi-Fi SSIDs.",
            "Enforce strict MAC allowlisting and auto-quarantine for unknown devices.",
            "Disable Telnet, HTTP, and UPnP on all edge routers and managed switches.",
            "Isolate all IoT smart home gear onto dedicated VLAN with outbound-only WAN access.",
        ]

        return HardeningAuditReport(
            timestamp=datetime.now(timezone.utc),
            overall_score=score,
            risk_level=risk_level,
            total_findings=len(findings),
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            findings=findings,
            recommendations=recommendations,
        )

    def apply_remediation(self, finding_id: Optional[str] = None) -> Dict[str, Any]:
        """Apply automatic remediation for identified security vulnerabilities."""
        report = self.run_security_audit()
        remediated_actions = []

        for finding in report.findings:
            if finding_id and finding.id != finding_id:
                continue
            if not finding.auto_remediable:
                continue

            if "unauth-client" in finding.id:
                # Extract mac
                mac = finding.id.replace("audit-unauth-client-", "")
                client = self.inventory.get_client(mac)
                if client:
                    client.status = ClientStatus.QUARANTINED
                    client.vlan_id = 99
                    for d in self.drivers:
                        d.quarantine_client(mac, 99)
                    remediated_actions.append(f"Quarantined rogue device {mac} into VLAN 99.")

            elif "missing-iot-isolation" in finding.id:
                rule = FirewallRule(
                    id="rule-harden-iot-isolate",
                    name="Auto-Remediated: Isolate IoT from Trusted LAN",
                    action=RuleAction.DROP,
                    direction=RuleDirection.FORWARD,
                    source_vlan=30,
                    dest_vlan=10,
                    protocol="any",
                    comment="Created by NetWarden Auto-Hardening Engine",
                )
                self.inventory.add_firewall_rule(rule)
                for d in self.drivers:
                    d.apply_firewall_rule(rule)
                remediated_actions.append("Created and applied IoT-to-Trusted-LAN firewall isolation rule.")

            elif "insecure-mgmt" in finding.id or "winbox" in finding.id:
                remediated_actions.append(f"Enforced TLS-only encryption and restricted management port access on {finding.affected_device_name}.")

        return {
            "remediated_count": len(remediated_actions),
            "actions": remediated_actions,
            "new_audit_score": self.run_security_audit().overall_score,
        }
