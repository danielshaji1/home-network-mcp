"""
NetWarden Configuration Loader and Settings.
Supports YAML file configuration and environment variables.
"""

from typing import Dict, List, Optional, Any
from pathlib import Path
import os
import yaml
from pydantic import BaseModel, Field
from netwarden.core.models import VendorType


class DeviceConfig(BaseModel):
    id: str
    name: str
    vendor: VendorType
    ip: str
    port: int = 443
    username: Optional[str] = "admin"
    password: Optional[str] = None
    api_key: Optional[str] = None
    verify_ssl: bool = False
    extra: Dict[str, Any] = Field(default_factory=dict)


class NetWardenSettings(BaseModel):
    network_name: str = "Home Lab Network"
    management_vlan: int = 1
    protected_ips: List[str] = Field(
        default_factory=lambda: ["127.0.0.1", "192.168.1.1", "10.0.1.1", "10.0.0.1"]
    )
    protected_macs: List[str] = Field(default_factory=list)
    devices: List[DeviceConfig] = Field(default_factory=list)
    terraform_working_dir: str = "./terraform"
    use_mock_driver: bool = True
    dry_run_default: bool = True


def load_config(config_path: Optional[str] = None) -> NetWardenSettings:
    """Load configuration from YAML file or environment defaults."""
    target_path = None
    if config_path:
        target_path = Path(config_path)
    elif os.environ.get("NETWARDEN_CONFIG"):
        target_path = Path(os.environ["NETWARDEN_CONFIG"])
    elif Path("netwarden.yaml").exists():
        target_path = Path("netwarden.yaml")
    elif Path("examples/multi_brand_hybrid.yaml").exists():
        target_path = Path("examples/multi_brand_hybrid.yaml")

    if target_path and target_path.exists():
        with open(target_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
            return NetWardenSettings(**raw)

    return NetWardenSettings()
