"""
Core integration modules for NetBox Automation Plugin

This package contains the core NAPALM and Nornir integration code.
Production version - direct connections only (NO SSH proxy support).
"""

from .napalm_integration import *
from .nornir_integration import *

__all__ = [
    'NornirDeviceManager',
    'NetBoxORMInventory',
]
