# Contributing to IDProva

Thank you for your interest in contributing to IDProva! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/idprova.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `cargo test --workspace`
6. Run linting: `cargo clippy --workspace`
7. Check formatting: `cargo fmt --all`
8. Commit with a descriptive message
9. Push and open a Pull Request

## Development Setup

### Prerequisites

- Rust stable (1.75+)
- Cargo
- Git

### Building

```bash
cargo build --workspace
```

### Testing

```bash
cargo test --workspace
```

### Formatting

```bash
cargo fmt --all
```

## What We're Looking For

### High Priority

- **Python SDK** — PyO3 bindings for `idprova-core`
- **TypeScript SDK** — napi-rs bindings for `idprova-core`
- **MCP Middleware** — Drop-in IDProva verification for MCP servers
- **A2A Integration** — IDProva authentication for Agent-to-Agent protocol
- **Documentation** — Guides, tutorials, and examples

### Always Welcome

- Bug reports with reproduction steps
- Test coverage improvements
- Documentation improvements
- Performance optimisations
- Additional compliance framework mappings (HIPAA, GDPR, etc.)

## Code Style

- Follow standard Rust conventions
- Use `cargo fmt` before committing
- All public APIs must have doc comments
- New features must include tests

## Commit Messages

Use clear, descriptive commit messages. For R&D tracking purposes, we appreciate the following format for significant changes:

```
Brief description of the change

Why: Explanation of the motivation
What: Summary of what changed
```

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for details. Do NOT open a public issue for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

## Questions?

Open a GitHub Discussion or reach out via the contact information on [idprova.dev](https://idprova.dev).
