# IDProva Python SDK — Quick-Start Guide

The IDProva Python SDK provides PyO3-based native bindings to the `idprova-core` Rust library. It exposes the full IDProva API surface — key generation, AID creation, DAT issuance and verification, scope checks, trust levels, and receipt logging — from Python 3.9+.

## Installation

The SDK is built with [Maturin](https://www.maturin.rs/). For development, install directly from source:

```bash
# Prerequisites: Rust toolchain (stable), Python 3.9+
pip install maturin

cd sdks/python
maturin develop --release
```

This compiles the Rust extension and installs it into the active Python environment. Verify:

```python
import idprova
print(idprova.__version__)
```

## Quick Start

The fastest path is `AgentIdentity`, a high-level convenience class that wraps key generation, AID building, and DAT issuance in one object.

```python
from idprova import AgentIdentity

# 1. Create an identity
identity = AgentIdentity.create("my-agent", domain="example.com")
print(identity.did)  # did:idprova:example.com:my-agent

# 2. Get the AID document
aid = identity.aid()
print(aid.trust_level)  # L0

# 3. Issue a DAT to another agent
dat = identity.issue_dat(
    subject_did="did:idprova:example.com:worker",
    scope=["mcp:mcp:tool:read", "mcp:mcp:tool:write"],
    expires_in_seconds=3600,
)
print(dat.issuer)   # did:idprova:example.com:my-agent
print(dat.subject)  # did:idprova:example.com:worker
print(dat.scope)    # ['mcp:mcp:tool:read', 'mcp:mcp:tool:write']

# 4. Serialize DAT for transport
compact = dat.to_compact()  # header.payload.signature (JWS)

# 5. Verify a received DAT
from idprova import DAT
received = DAT.from_compact(compact)
is_valid = received.verify_signature(identity.public_key_bytes)
print(is_valid)  # True
```

## Key Management

`KeyPair` provides Ed25519 key generation and raw signing. The private key is held in Rust memory and is never directly exposed to Python.

```python
from idprova import KeyPair

# Generate a new key pair
kp = KeyPair.generate()
print(kp.public_key_multibase)  # z... (base58btc)
print(len(kp.public_key_bytes))  # 32

# Sign and verify arbitrary bytes
message = b"agent action payload"
signature = kp.sign(message)
assert kp.verify(message, signature) is True

# Load a key from stored secret bytes (32 bytes)
# WARNING: only use for previously saved keys
kp2 = KeyPair.from_secret_bytes(secret_bytes)
```

> **Key storage:** The SDK does not persist keys — your application is responsible for storing `secret_bytes` securely (e.g., in a secrets manager or encrypted vault).

## Creating an AID Manually

Use `AIDBuilder` when you need full control over the identity document:

```python
from idprova import KeyPair, AIDBuilder, AID

kp = KeyPair.generate()

builder = AIDBuilder()
builder.id("did:idprova:example.com:my-agent")
builder.controller("did:idprova:example.com:alice")
builder.name("My Agent")
builder.description("Reads and summarises documents")
builder.model("gpt-4o")
builder.runtime("python-3.12")
builder.trust_level("L1")
builder.add_ed25519_key(kp)

aid = builder.build()
aid.validate()

# Persist to JSON
json_str = aid.to_json()

# Load from JSON
restored = AID.from_json(json_str)
assert restored.did == aid.did
```

## Issuing a DAT (Low-Level)

Use `DAT.issue()` directly when issuing on behalf of a key pair that is not wrapped in an `AgentIdentity`:

```python
from idprova import KeyPair, DAT

issuer_kp = KeyPair.generate()

dat = DAT.issue(
    issuer_did="did:idprova:example.com:alice",
    subject_did="did:idprova:example.com:agent",
    scope=["mcp:mcp:tool:read"],
    expires_in_seconds=3600,
    signing_key=issuer_kp,
    max_actions=500,       # optional: cap on action count
    require_receipt=True,  # optional: enforce receipt logging
)

print(dat.jti)        # dat_<uuid>
print(dat.issuer)     # did:idprova:example.com:alice
print(dat.subject)    # did:idprova:example.com:agent
print(dat.expires_at) # Unix timestamp
print(dat.is_expired) # False

dat.validate_timing()  # raises ValueError if expired or not-yet-valid
```

### Verifying a DAT

```python
from idprova import DAT

# Parse from compact JWS received in HTTP header or message
dat = DAT.from_compact(compact_token)

# Check timing
dat.validate_timing()  # raises ValueError("DatExpiredError") if expired

# Verify cryptographic signature
# issuer_pubkey_bytes must be the 32-byte public key of the issuer
if not dat.verify_signature(issuer_pubkey_bytes):
    raise PermissionError("invalid DAT signature")

# Inspect claims
print(dat.scope)   # ['mcp:mcp:tool:read']
print(dat.issuer)  # did:idprova:...
```

## Scopes

`Scope` validates and matches permission strings in `namespace:protocol:resource:action` format. Wildcards (`*`) are supported in the protocol, resource, and action positions.

```python
from idprova import Scope

# Parse a scope
s = Scope("mcp:mcp:tool:read")
print(str(s))  # mcp:mcp:tool:read

# Wildcard coverage check
broad = Scope("mcp:*:*:*")
narrow = Scope("mcp:mcp:tool:read")
assert broad.covers(narrow)      # True — broad permits narrow
assert not narrow.covers(broad)  # False — narrow does not permit broad

# Exact match
s1 = Scope("mcp:mcp:tool:read")
s2 = Scope("mcp:mcp:tool:read")
assert s1.covers(s2)  # True

# Invalid scope raises
try:
    Scope("invalid")  # missing protocol:resource:action parts
except Exception as e:
    print(e)
```

**Scope grammar:** `namespace:protocol:resource:action` — all four segments required. Use `*` for wildcard segments.

## Trust Levels

```python
from idprova import TrustLevel

l0 = TrustLevel("L0")  # Self-attested (default)
l1 = TrustLevel("L1")  # Operator-attested
l2 = TrustLevel("L2")  # CA-signed certificate
l3 = TrustLevel("L3")  # Multi-party attestation
l4 = TrustLevel("L4")  # Hardware-attested (TPM/TEE)

print(l0.description)  # human-readable label

# Minimum-level check
assert not l0.meets_minimum(l1)   # L0 does not meet L1 requirement
assert l4.meets_minimum(l1)       # L4 meets L1 requirement

# Invalid level raises
try:
    TrustLevel("L5")
except ValueError:
    pass  # "Invalid trust level"
```

## Receipt Log

`ReceiptLog` provides an append-only, hash-chained audit trail. Use it to record agent actions for compliance and non-repudiation.

```python
from idprova import ReceiptLog

log = ReceiptLog()
print(len(log))           # 0
print(log.last_hash)      # "genesis"
print(log.next_sequence)  # 0

# Receipts are appended via the CLI or registry — the Python SDK
# exposes the log for reading and integrity verification.
log.verify_integrity()  # raises on tampering

# Serialize for persistence or transmission
json_str = log.to_json()
```

> **Note:** Receipt entries are appended through the `idprova receipt` CLI command or the registry server. The Python SDK log object is used for verification and serialization of logs received from those sources.

## Error Handling

All IDProva errors are standard Python exceptions:

| Condition | Exception type | Message pattern |
|-----------|---------------|-----------------|
| Expired DAT | `ValueError` | `DatExpiredError` |
| Algorithm confusion | `ValueError` | `unsupported algorithm` |
| Invalid trust level | `ValueError` | `Invalid trust level` |
| Invalid scope | `ValueError` | parse error message |
| Bad secret key | `ValueError` | `32 bytes` |
| AID validation | `ValueError` | validation error message |

```python
from idprova import DAT, KeyPair

kp = KeyPair.generate()
dat = DAT.issue("did:idprova:a:b", "did:idprova:a:c", ["mcp:*:*:*"], -1, kp)

try:
    dat.validate_timing()
except ValueError as e:
    print(e)  # DatExpiredError: token expired at ...
```

## Complete Example

```python
"""
End-to-end example: create two agents, issue a scoped DAT,
verify it, check scopes, and log an action receipt.
"""
from idprova import AgentIdentity, DAT, Scope, ReceiptLog

# --- Issuer (orchestrator) ---
orchestrator = AgentIdentity.create("orchestrator", domain="example.com")
print(f"Orchestrator: {orchestrator.did}")

# --- Subject (worker agent) ---
worker = AgentIdentity.create("worker", domain="example.com")
print(f"Worker:       {worker.did}")

# --- Issue a scoped DAT ---
dat = orchestrator.issue_dat(
    subject_did=worker.did,
    scope=["mcp:mcp:tool:read", "mcp:mcp:tool:write"],
    expires_in_seconds=3600,
)
compact = dat.to_compact()
print(f"DAT (compact): {compact[:60]}...")

# --- Worker receives and verifies the DAT ---
received_dat = DAT.from_compact(compact)
received_dat.validate_timing()

is_valid = received_dat.verify_signature(orchestrator.public_key_bytes)
assert is_valid, "DAT signature invalid"

# --- Check if granted scope covers the required action ---
granted = [Scope(s) for s in received_dat.scope]
required = Scope("mcp:mcp:tool:read")
has_permission = any(g.covers(required) for g in granted)
assert has_permission, "missing required scope"

print("All checks passed — worker authorised to call mcp:mcp:tool:read")

# --- Audit log ---
log = ReceiptLog()
log.verify_integrity()
print(f"Receipt log entries: {len(log)}")
```

## API Reference Summary

| Class | Key methods / properties |
|-------|--------------------------|
| `KeyPair` | `.generate()`, `.from_secret_bytes(b)`, `.sign(msg)`, `.verify(msg, sig)`, `.public_key_bytes`, `.public_key_multibase` |
| `AID` | `.from_json(s)`, `.to_json()`, `.validate()`, `.did`, `.controller`, `.trust_level` |
| `AIDBuilder` | `.id()`, `.controller()`, `.name()`, `.trust_level()`, `.add_ed25519_key()`, `.build()` |
| `DAT` | `.issue(...)`, `.from_compact(s)`, `.to_compact()`, `.verify_signature(b)`, `.validate_timing()`, `.is_expired`, `.scope`, `.issuer`, `.subject` |
| `Scope` | `Scope(s)`, `.covers(other)` |
| `TrustLevel` | `TrustLevel(s)`, `.meets_minimum(other)`, `.description` |
| `ReceiptLog` | `.verify_integrity()`, `.to_json()`, `.last_hash`, `.next_sequence`, `len(log)` |
| `AgentIdentity` | `.create(name, domain)`, `.aid()`, `.keypair()`, `.issue_dat(...)`, `.public_key_bytes`, `.did` |

## See Also

- [Core Library API Reference](core-api.md)
- [Protocol Concepts](concepts.md)
- [Getting Started (CLI)](getting-started.md)
- [TypeScript SDK Quick-Start](sdk-typescript.md)
