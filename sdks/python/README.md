# IDProva Python SDK

Verifiable identity for the agent era. Ed25519-based agent identity, scoped delegation tokens, and hash-chained audit receipts.

## Install

```bash
pip install idprova
```

## Quick Start

```python
from idprova import AgentIdentity

# Create an agent identity
identity = AgentIdentity.create("my-agent", domain="example.com")
print(identity.did)  # did:idprova:example.com:my-agent

# Issue a delegation token
dat = identity.issue_dat(
    "did:idprova:example.com:sub-agent",
    ["mcp:tool:read"],
    expires_in_seconds=3600,
)
print(dat.to_compact())  # JWS compact serialization
```

## Documentation

See [idprova.dev](https://idprova.dev) for full documentation.

## License

Apache-2.0
