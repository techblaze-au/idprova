# IDProva Python SDK
# Provides AI agent identity, delegation tokens, and action receipts.
#
# This SDK wraps the Rust core library via PyO3 for maximum performance
# and cryptographic correctness.
#
# Usage:
#   from idprova import AgentIdentity, KeyPair, AID, DAT
#
# Quick start:
#   identity = AgentIdentity.create("my-agent", domain="example.com")
#   print(identity.did)
#
# For more information, see: https://idprova.dev

__version__ = "0.1.0"

# Import all types from the native Rust module (built by maturin/PyO3)
from idprova.idprova import (  # noqa: F401
    AgentIdentity,
    AID,
    AIDBuilder,
    DAT,
    KeyPair,
    ReceiptLog,
    Scope,
    TrustLevel,
)

__all__ = [
    "AgentIdentity",
    "AID",
    "AIDBuilder",
    "DAT",
    "KeyPair",
    "ReceiptLog",
    "Scope",
    "TrustLevel",
    "__version__",
]
