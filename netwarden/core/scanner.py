"""
NetWarden Local Network Discovery & Subnet Scanner.
Discovers real-life physical devices, default gateways, and ARP entries on the active LAN.
"""

from typing import List, Dict, Any, Optional, Tuple
import subprocess
import re
import socket
import ipaddress
import platform
from datetime import datetime, timezone
from netwarden.core.models import (
    ConnectedClient,
    ClientStatus,
    NetworkDevice,
    DeviceType,
    DeviceStatus,
    VendorType,
)
from netwarden.core.inventory import NetworkInventory


# Common MAC OUI database for instant vendor fingerprinting
OUI_DATABASE: Dict[str, str] = {
    "14:55:b9": "Arris / AT&T Fiber Gateway",
    "bc:f4:d4": "Apple, Inc.",
    "00:11:22": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.",
    "3c:22:fb": "Apple, Inc.",
    "74:83:c2": "Ubiquiti Networks",
    "fc:ec:da": "Ubiquiti Networks",
    "48:8f:5a": "MikroTik",
    "cc:2d:e0": "MikroTik",
    "b8:27:eb": "Raspberry Pi Trading",
    "dc:a6:32": "Raspberry Pi Trading",
    "d8:3a:dd": "Raspberry Pi Trading",
    "24:62:ab": "Espressif (IoT Device)",
    "30:ae:a4": "Espressif (IoT Device)",
    "84:0d:8e": "Espressif (IoT Device)",
    "a4:e5:7c": "Espressif / Tuya Smart",
    "50:02:91": "Amazon (Echo / Ring)",
    "68:54:fd": "Amazon (Echo / Ring)",
    "d8:6c:63": "Google / Nest",
    "54:60:09": "Google / Nest",
    "f4:f5:e8": "Google / Nest",
    "00:50:56": "VMware Virtual Host",
    "00:0c:29": "VMware Virtual Host",
}


def lookup_oui(mac: str) -> str:
    """Lookup vendor name from MAC address OUI prefix."""
    normalized = mac.lower().replace("-", ":")
    prefix = ":".join(normalized.split(":")[:3])
    return OUI_DATABASE.get(prefix, "Unknown Vendor")


def get_default_gateway_and_ip() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Determine default gateway IP, host local IP, and interface name.
    Supports macOS and Linux.
    """
    gateway_ip = None
    interface = None
    local_ip = None

    try:
        if platform.system() == "Darwin":
            proc = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=3)
            for line in proc.stdout.splitlines():
                if "gateway:" in line:
                    gateway_ip = line.split(":", 1)[1].strip()
                elif "interface:" in line:
                    interface = line.split(":", 1)[1].strip()

            if interface:
                ifconfig = subprocess.run(["ifconfig", interface], capture_output=True, text=True, timeout=3)
                for line in ifconfig.stdout.splitlines():
                    if "inet " in line:
                        parts = line.strip().split()
                        local_ip = parts[1]
                        break
        else:
            # Linux fallback via ip route
            proc = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
            # Example: default via 192.168.1.1 dev eth0
            parts = proc.stdout.strip().split()
            if len(parts) >= 5 and parts[1] == "via":
                gateway_ip = parts[2]
                interface = parts[4]
    except Exception:
        pass

    return gateway_ip, local_ip, interface


def read_arp_table() -> List[Dict[str, str]]:
    """Parse OS ARP cache table to extract active IP/MAC tuples."""
    entries = []
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        for line in proc.stdout.splitlines():
            # Matches: ? (192.168.1.100) at bc:f4:d4:43:94:79 on en0
            m = re.search(
                r"\((192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)",
                line,
            )
            if m:
                ip = m.group(1)
                mac = m.group(2).lower()
                if mac != "ff:ff:ff:ff:ff:ff" and not ip.endswith(".255"):
                    # Normalize MAC format to standard 2-digit pairs
                    mac_parts = [f"{int(x, 16):02x}" for x in mac.split(":") if x]
                    if len(mac_parts) == 6:
                        normalized_mac = ":".join(mac_parts)
                        entries.append({"ip": ip, "mac": normalized_mac})
    except Exception:
        pass
    return entries


def scan_live_network_environment(inventory: NetworkInventory) -> Dict[str, Any]:
    """
    Scans the local physical subnet, identifies the gateway, resolves hostnames,
    fingerprints vendor OUIs, and populates the unified inventory with real devices.
    """
    gateway_ip, local_ip, iface = get_default_gateway_and_ip()
    arp_entries = read_arp_table()

    discovered_clients = []
    gateway_device = None

    for entry in arp_entries:
        ip = entry["ip"]
        mac = entry["mac"]
        vendor = lookup_oui(mac)
        is_gw = (ip == gateway_ip)

        # Reverse DNS lookup for local hostname
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = f"host-{ip.split('.')[-1]}"

        # Categorize device
        category = "Workstation"
        if "Espressif" in vendor or "Tuya" in vendor or "Nest" in vendor or "Amazon" in vendor:
            category = "IoT"
        elif "Raspberry" in vendor:
            category = "Server"
        elif is_gw:
            category = "Gateway"

        if is_gw:
            # Add or update gateway in inventory
            gateway_device = NetworkDevice(
                id="live-gateway-01",
                name=f"Physical Gateway ({vendor})",
                vendor=VendorType.GENERIC if not "Ubiquiti" in vendor else VendorType.UNIFI,
                device_type=DeviceType.GATEWAY,
                ip_address=ip,
                mac_address=mac,
                model=vendor,
                status=DeviceStatus.ONLINE,
                management_ip=ip,
                metadata={"interface": iface, "discovery_method": "live_arp"},
            )
            inventory.add_device(gateway_device)
        else:
            client = ConnectedClient(
                mac_address=mac,
                ip_address=ip,
                hostname=hostname,
                vendor_oui=vendor,
                vlan_id=1,
                device_category=category,
                status=ClientStatus.ALLOWED if ip == local_ip else ClientStatus.PENDING_APPROVAL,
                notes=f"Discovered on physical interface {iface or 'LAN'}",
            )
            inventory.add_client(client)
            discovered_clients.append(client)

    return {
        "success": True,
        "interface": iface,
        "host_ip": local_ip,
        "gateway_ip": gateway_ip,
        "gateway_vendor": lookup_oui(gateway_device.mac_address) if gateway_device else "Unknown",
        "devices_found_count": len(discovered_clients) + (1 if gateway_device else 0),
        "gateway": gateway_device.model_dump() if gateway_device else None,
        "clients": [c.model_dump() for c in discovered_clients],
    }
