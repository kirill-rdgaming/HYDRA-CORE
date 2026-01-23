"""
HYDRA7 - A secure mesh network with built-in DPI evasion and multi-hop routing.

This package provides a production-ready implementation of the HYDRA7 protocol
for building secure, distributed proxy networks.
"""

__version__ = "1.0.0"
__author__ = "HYDRA Development Team"

# Import core components for public API
from hydra7.core import (
    HydraNode,
    SessionCrypto,
    SecureSocket,
    PeerManager,
    StunClient,
    Obfuscator,
    NETWORK_SECRET,
    HYDRA_PORT_BASE,
    SOCKS_PORT,
)

__all__ = [
    "HydraNode",
    "SessionCrypto",
    "SecureSocket",
    "PeerManager",
    "StunClient",
    "Obfuscator",
    "NETWORK_SECRET",
    "HYDRA_PORT_BASE",
    "SOCKS_PORT",
    "__version__",
]
