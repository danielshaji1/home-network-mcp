"""
NetWarden Exceptions Hierarchy.
"""

class NetWardenError(Exception):
    """Base exception for all NetWarden errors."""
    pass


class SafetyLockoutError(NetWardenError):
    """Raised when an operation would isolate the management plane or lock out the administrator."""
    pass


class DriverError(NetWardenError):
    """Raised when a device driver fails to communicate or execute an action."""
    pass


class AuthenticationError(DriverError):
    """Raised when authentication to a network device fails."""
    pass


class DeviceNotFoundError(DriverError):
    """Raised when a requested device is not found in the topology."""
    pass


class TerraformExecutionError(NetWardenError):
    """Raised when Terraform plan or apply fails."""
    pass


class ConfigurationValidationError(NetWardenError):
    """Raised when network configuration or VLAN layout is invalid."""
    pass


class RollbackError(NetWardenError):
    """Raised when restoring a previous configuration backup fails."""
    pass
