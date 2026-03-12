# idprova-middleware

Tower/Axum middleware layer for IDProva DAT bearer token verification.

Drop-in middleware that validates DAT bearer tokens on incoming HTTP requests, enforcing delegation constraints and checking token expiry.

## Usage

```toml
[dependencies]
idprova-middleware = "0.1"
```

```rust
use idprova_middleware::IdprovaLayer;

let app = Router::new()
    .route("/api/action", post(handler))
    .layer(IdprovaLayer::new(verifier));
```

## License

Apache-2.0
