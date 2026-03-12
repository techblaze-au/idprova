# idprova-registry

HTTP registry service for IDProva Agent Identity Document (AID) resolution and management.

Built with Axum and SQLite. Provides REST endpoints for:
- AID registration and lookup
- Identity resolution
- Delegation token validation

## Usage

As a library:
```toml
[dependencies]
idprova-registry = "0.1"
```

As a standalone server:
```bash
cargo install idprova-registry
idprova-registry --port 3000
```

## License

Apache-2.0
