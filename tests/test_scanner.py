"""
Unit tests for NetWarden physical network discovery and ARP scanner.
"""

from netwarden.core.scanner import (
    lookup_oui,
    get_default_gateway_and_ip,
    read_arp_table,
    scan_live_network_environment,
)
from netwarden.core.inventory import NetworkInventory


def test_oui_vendor_lookup():
    assert lookup_oui("14:55:b9:06:1c:22") == "Arris / AT&T Fiber Gateway"
    assert lookup_oui("bc:f4:d4:43:94:79") == "Apple, Inc."
    assert lookup_oui("b8:27:eb:aa:bb:cc") == "Raspberry Pi Trading"
    assert lookup_oui("ff:99:88:77:66:55") == "Unknown Vendor"


def test_scan_live_network_environment(tmp_path):
    inv = NetworkInventory(str(tmp_path / "test_scan.json"))
    res = scan_live_network_environment(inv)
    assert res["success"] is True
    assert "devices_found_count" in res
