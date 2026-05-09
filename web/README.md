# Web demo (`idprova-demo`)

A browser-only React app that exercises the IDProva primitives in-page using `@noble/ed25519` and `@noble/hashes`. There is no server-side code here — keypairs, AIDs, and DATs are all generated and signed in the browser.

This is not a production frontend. It exists so contributors and curious readers can click through the same operations the CLI performs and see their structure (key formats, AID JSON, DAT JWS) without installing Rust.

## What's in `src/`

- `App.tsx` — top-level shell. Switches between tabs.
- `components/` — one panel per protocol concept:
  - `KeygenPanel` — Ed25519 keypair generation.
  - `AidPanel` — build and inspect AID documents.
  - `DatPanel` — issue and verify Delegation Attestation Tokens.
  - `RevocationPanel` — exercise the registry's revocation routes.
  - `ReceiptPanel` — sign and chain action receipts.
  - `DashboardPanel` — overview of session state.
- `crypto/` — Ed25519 + BLAKE3 helpers shared across panels.
- `protocol/` — pure functions that build the same JSON shapes the Rust core emits.
- `store/keys.tsx` — React context that holds the in-session keypairs (lost on page refresh; never persisted).
- `api/` — fetch wrappers that talk to a registry URL the user pastes in.

## Run it locally

```bash
cd web
npm install
npm run dev          # serves on http://localhost:5173 by default
```

Pasting a registry URL (e.g. `http://localhost:3000` after `cargo run -p idprova-registry`) into the top bar lets the app publish/resolve AIDs and check revocations. Everything works offline as well — keys, AIDs, and DATs are constructed without the registry.

## Build

```bash
npm run build        # TypeScript check + Vite production build → dist/
npm run preview      # serves the built artifact locally
```

There are no automated tests in this directory; protocol correctness lives in the Rust crates and their test suites.
