# idprova-core

Core library for the IDProva protocol -- AI agent identity, delegation, and audit.

Provides:
- Agent Identity Documents (AIDs) with Ed25519 key pairs
- Delegation Attestation Tokens (DATs) for scoped capability delegation
- Hash-chained audit receipts (BLAKE3)
- RBAC constraint engine with policy evaluation
- Post-quantum readiness hooks

## Usage

```toml
[dependencies]
idprova-core = "0.1"
```

```rust
use idprova_core::aid::AgentIdentityDocument;

let aid = AgentIdentityDocument::generate("my-agent")?;
```

## License

Apache-2.0
