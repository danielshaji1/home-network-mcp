"""
NetWarden Data Models and Pydantic Schemas.
Unified representations across heterogeneous network brands.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class VendorType(str, Enum):
    UNIFI = "unifi"
    MIKROTIK = "mikrotik"
    OPNSENSE = "opnsense"
    OPENWRT = "openwrt"
    CISCO = "cisco"
    PIHOLE = "pihole"
    MOCK = "mock"


class DeviceType(str, Enum):
    GATEWAY = "gateway"
    ROUTER = "router"
    SWITCH = "switch"
    ACCESS_POINT = "access_point"
    SINKHOLE = "sinkhole"


class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    UNCONFIGURED = "unconfigured"


class PortMode(str, Enum):
    ACCESS = "access"
    TRUNK = "trunk"
    ISOLATED = "isolated"


class PortInfo(BaseModel):
    port_number: int
    name: str = ""
    enabled: bool = True
    link_up: bool = False
    speed_mbps: int = 1000
    duplex: str = "full"
    mode: PortMode = PortMode.ACCESS
    pvid: int = 1  # Native VLAN
    allowed_vlans: List[int] = Field(default_factory=lambda: [1])
    poe_enabled: bool = False
    poe_power_watts: float = 0.0
    connected_mac: Optional[str] = None
    crc_errors: int = 0
    packet_drops: int = 0


class NetworkDevice(BaseModel):
    id: str
    name: str
    vendor: VendorType
    device_type: DeviceType
    ip_address: str
    mac_address: str
    model: str = "Generic"
    firmware_version: str = "1.0.0"
    status: DeviceStatus = DeviceStatus.ONLINE
    uptime_seconds: int = 86400
    ports: List[PortInfo] = Field(default_factory=list)
    active_vlans: List[int] = Field(default_factory=lambda: [1])
    management_ip: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ClientStatus(str, Enum):
    ALLOWED = "allowed"
    PENDING_APPROVAL = "pending_approval"
    QUARANTINED = "quarantined"
    BLOCKED = "blocked"


class ConnectedClient(BaseModel):
    mac_address: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor_oui: Optional[str] = "Unknown"
    vlan_id: int = 1
    device_category: str = "General"  # IoT, Workstation, Mobile, Server, Entertainment
    status: ClientStatus = ClientStatus.ALLOWED
    switch_id: Optional[str] = None
    switch_port: Optional[int] = None
    ssid: Optional[str] = None
    is_wireless: bool = False
    dhcp_reservation: bool = False
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: Optional[str] = None


class VLANPurpose(str, Enum):
    MANAGEMENT = "management"
    TRUSTED_LAN = "trusted_lan"
    IOT = "iot"
    GUEST = "guest"
    DMZ = "dmz"
    QUARANTINE = "quarantine"


class IsolationLevel(str, Enum):
    ISOLATED = "isolated"              # No communication with any other local VLAN or internet
    INTERNET_ONLY = "internet_only"    # Can access WAN, completely blocked from local private subnets
    RESTRICTED = "restricted"          # Specific pinned ports/destinations only
    ROUTED = "routed"                  # Standard routed private subnet


class VLANDefinition(BaseModel):
    vlan_id: int
    name: str
    subnet_cidr: str
    gateway_ip: str
    dhcp_start: str
    dhcp_end: str
    purpose: VLANPurpose
    isolation_level: IsolationLevel = IsolationLevel.ROUTED
    dns_servers: List[str] = Field(default_factory=lambda: ["1.1.1.1", "9.9.9.9"])
    description: str = ""


class RuleAction(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"


class RuleDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    FORWARD = "forward"


class FirewallRule(BaseModel):
    id: str
    name: str
    action: RuleAction = RuleAction.DROP
    direction: RuleDirection = RuleDirection.FORWARD
    source_vlan: Optional[int] = None
    source_ip_or_cidr: Optional[str] = None
    dest_vlan: Optional[int] = None
    dest_ip_or_cidr: Optional[str] = None
    protocol: str = "any"  # tcp, udp, icmp, any
    dest_ports: List[int] = Field(default_factory=list)
    enabled: bool = True
    logging: bool = True
    comment: str = ""


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HardeningFinding(BaseModel):
    id: str
    severity: SeverityLevel
    category: str  # Management, Wi-Fi, Isolation, Layer2, Gateway
    title: str
    affected_device_id: str
    affected_device_name: str
    description: str
    risk: str
    remediation_suggestion: str
    auto_remediable: bool = True


class HardeningAuditReport(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    overall_score: int  # 0 to 100
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[HardeningFinding] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class DiagnosticResult(BaseModel):
    target: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reachable: bool
    latency_ms: Optional[float] = None
    packet_loss_pct: float = 0.0
    dns_resolves: bool = True
    resolved_ip: Optional[str] = None
    gateway_reachable: bool = True
    hop_count: Optional[int] = None
    port_checks: Dict[int, bool] = Field(default_factory=dict)
    switch_port_errors: int = 0
    root_cause: str = "None detected"
    recommended_action: str = "Network path is healthy"


class TerraformPlanSummary(BaseModel):
    resources_to_add: int = 0
    resources_to_change: int = 0
    resources_to_destroy: int = 0
    changes_detail: List[Dict[str, Any]] = Field(default_factory=list)
    risk_assessment: str = "LOW"
    raw_plan_output: str = ""
    is_safe_to_apply: bool = True
