# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in IDProva, please report it responsibly:

1. **Do NOT** file a public GitHub issue
2. Email: security@techblaze.com.au (or security@idprova.dev when available)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for resolution.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Considerations

IDProva is a security-critical protocol. We take the following measures:

- All cryptographic operations use audited libraries (`ed25519-dalek`, `blake3`)
- No custom cryptographic implementations
- Regular dependency audits via `cargo audit`
- Fuzz testing of parsers (AID, DAT, scope)
- Property-based testing of cryptographic operations

## Cryptographic Algorithms

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Signatures | Ed25519 | `ed25519-dalek` v2 (audited) |
| Hashing | BLAKE3 | `blake3` crate |
| Interop hashing | SHA-256 | `sha2` crate |

Post-quantum support (ML-DSA-65/87) is planned for a future release.
