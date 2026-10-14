"""
NetWarden Device Drivers Package and Factory.
"""

from typing import Dict, Any, Type
from netwarden.drivers.base import BaseDeviceDriver
from netwarden.drivers.mock import MockDeviceDriver
from netwarden.drivers.unifi import UniFiDriver
from netwarden.drivers.mikrotik import MikrotikDriver
from netwarden.drivers.opnsense import OpnsenseDriver
from netwarden.drivers.openwrt import OpenWrtDriver
from netwarden.drivers.cisco import CiscoDriver
from netwarden.drivers.pihole import PiholeDriver
from netwarden.core.models import VendorType


DRIVER_REGISTRY: Dict[VendorType, Type[BaseDeviceDriver]] = {
    VendorType.MOCK: MockDeviceDriver,
    VendorType.UNIFI: UniFiDriver,
    VendorType.MIKROTIK: MikrotikDriver,
    VendorType.OPNSENSE: OpnsenseDriver,
    VendorType.OPENWRT: OpenWrtDriver,
    VendorType.CISCO: CiscoDriver,
    VendorType.PIHOLE: PiholeDriver,
}


def create_driver(
    vendor: VendorType,
    device_id: str,
    name: str,
    ip: str,
    force_mock: bool = False,
    **kwargs,
) -> BaseDeviceDriver:
    """Factory function to instantiate the appropriate driver."""
    if force_mock:
        return MockDeviceDriver(
            device_id=device_id,
            name=name,
            ip=ip,
            vendor=vendor,
            **kwargs,
        )

    driver_cls = DRIVER_REGISTRY.get(vendor)
    if not driver_cls:
        # Fallback to mock driver with specified vendor metadata
        return MockDeviceDriver(device_id=device_id, name=name, ip=ip, vendor=vendor, **kwargs)

    return driver_cls(device_id=device_id, name=name, ip=ip, **kwargs)
