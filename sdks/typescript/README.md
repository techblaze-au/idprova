# TypeScript SDKs

Native bindings to the IDProva Rust core, packaged for Node.js via [napi-rs](https://napi.rs/). Today this directory holds a single package; the `packages/` layout is here so additional SDKs (e.g. browser-only, Deno) can be added without restructuring.

## Layout

- `packages/core/` — `@idprova/core` on npm. Wraps the Rust `idprova-core` crate (crypto, AID, DAT, receipt) as a native Node addon. See `packages/core/package.json`.

## Building from source

The package compiles a Rust crate, so you need both Node and a Rust toolchain.

```bash
cd sdks/typescript/packages/core
npm install
npm run build           # release build → produces a *.node binary + index.{js,d.ts}
npm run build:debug     # debug build, faster iteration
```

## Running the package's tests

```bash
cd sdks/typescript/packages/core
npm test
```

Tests live under `packages/core/__test__/` and run with Vitest. They drive the compiled native binding directly, so `npm run build` (or `build:debug`) must succeed first.

## Installing the published package

Application code should depend on the published package, not on this directory:

```bash
npm install @idprova/core
```

The npm release is built and published from `.github/workflows/npm-publish.yml` for Linux, macOS, and Windows. Release artifacts are platform-specific `*.node` files alongside `index.js` / `index.d.ts`.

## Generated files

The build emits binaries that are gitignored (`*.node`, `target/`). Don't commit them.
