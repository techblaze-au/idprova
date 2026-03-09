# IDProva TypeScript SDK — Quick-Start Guide

The IDProva TypeScript SDK provides napi-rs native bindings to the `idprova-core` Rust library. It targets Node.js 18+ and ships as the `@idprova/core` package. All crypto runs natively in Rust — no WebCrypto, no pure-JS fallbacks.

## Installation

The SDK is built with [napi-rs](https://napi.rs/). For development, build from source:

```bash
# Prerequisites: Rust toolchain (stable), Node.js 18+
npm install -g @napi-rs/cli

cd sdks/typescript/packages/core
npm install
npm run build     # release build
```

This compiles the native `.node` addon and writes loader shims (`index.js`, `index.d.ts`). Verify:

```typescript
import { AgentIdentity } from '@idprova/core';
const identity = AgentIdentity.create('test');
console.log(identity.did);
```

## Quick Start

`AgentIdentity` is the high-level entry point — it wraps key generation, AID creation, and DAT issuance.

```typescript
import { AgentIdentity, DAT } from '@idprova/core';

// 1. Create an identity
const identity = AgentIdentity.create('my-agent', 'example.com');
console.log(identity.did);  // did:idprova:example.com:my-agent

// 2. Get the AID document
const aid = identity.aid();
console.log(aid.trustLevel);  // 'L0'

// 3. Issue a DAT to another agent
const dat = identity.issueDat(
  'did:idprova:example.com:worker',
  ['mcp:tool:filesystem:read', 'mcp:tool:filesystem:write'],
  3600,  // expires in 1 hour
);
console.log(dat.issuer);   // did:idprova:example.com:my-agent
console.log(dat.subject);  // did:idprova:example.com:worker
console.log(dat.scope);    // ['mcp:tool:filesystem:read', 'mcp:tool:filesystem:write']

// 4. Serialize DAT for transport (JWS compact)
const compact = dat.toCompact();  // "header.payload.signature"

// 5. Verify a received DAT
const received = DAT.fromCompact(compact);
const isValid = received.verifySignature(identity.publicKeyBytes);
console.log(isValid);  // true
```

## Key Management

`KeyPair` provides Ed25519 key generation and raw signing. The private key lives in Rust memory and is never returned to JavaScript.

```typescript
import { KeyPair } from '@idprova/core';

// Generate a new key pair
const kp = KeyPair.generate();
console.log(kp.publicKeyMultibase);    // z... (base58btc)
console.log(kp.publicKeyBytes.length); // 32

// Sign and verify arbitrary bytes
const message = Buffer.from('agent action payload');
const signature = kp.sign(message);
console.log(kp.verify(message, signature));  // true

// Load from stored secret bytes (32 bytes)
// WARNING: only use for previously saved keys
const kp2 = KeyPair.fromSecretBytes(secretBytes);
```

> **Key storage:** The SDK does not persist keys — your application is responsible for securely storing the 32-byte secret (e.g., in a secrets manager or encrypted store).

## Creating an AID Manually

Use `AIDBuilder` for full control over the identity document:

```typescript
import { KeyPair, AIDBuilder, AID } from '@idprova/core';

const kp = KeyPair.generate();

const builder = new AIDBuilder();
builder.setId('did:idprova:example.com:my-agent');
builder.setController('did:idprova:example.com:alice');
builder.setName('My Agent');
builder.setDescription('Reads and summarises documents');
builder.setModel('gpt-4o');
builder.setRuntime('node-22');
builder.setTrustLevel('L1');
builder.addEd25519Key(kp);

const aid = builder.build();
aid.validate();

// Persist to JSON
const jsonStr = aid.toJson();

// Load from JSON
const restored = AID.fromJson(jsonStr);
console.log(restored.did === aid.did);  // true
```

## Issuing a DAT (Low-Level)

Use `DAT.issue()` directly when the signing key is not wrapped in an `AgentIdentity`:

```typescript
import { KeyPair, DAT } from '@idprova/core';

const issuerKp = KeyPair.generate();

const dat = DAT.issue(
  'did:idprova:example.com:alice',   // issuerDid
  'did:idprova:example.com:agent',   // subjectDid
  ['mcp:tool:search:execute'],         // scope
  3600,                               // expiresInSeconds
  issuerKp,                           // signingKey
  500,   // maxActions (optional)
  true,  // requireReceipt (optional)
);

console.log(dat.jti);        // dat_<uuid>
console.log(dat.issuer);     // did:idprova:example.com:alice
console.log(dat.subject);    // did:idprova:example.com:agent
console.log(dat.expiresAt);  // Unix timestamp (number)
console.log(dat.isExpired);  // false

dat.validateTiming();  // throws if expired or not-yet-valid
```

### Verifying a DAT

```typescript
import { DAT, EvaluationContext } from '@idprova/core';

// Parse from compact JWS received in HTTP header or message
const dat = DAT.fromCompact(compactToken);

// Option 1: Signature-only check
if (!dat.verifySignature(issuerPubKeyBytes)) {
  throw new Error('invalid DAT signature');
}

// Option 2: Full verification pipeline (signature + timing + scope + constraints)
const ctx = new EvaluationContext();
ctx.request_ip = '192.168.1.10';
ctx.agent_trust_level = 50;
ctx.actions_in_window = 5;

dat.verify(
  issuerPubKeyBytes,
  'mcp:tool:search:execute',  // required scope
  ctx,
);
// Throws Error with details if any check fails

// Inspect claims
console.log(dat.scope);   // ['mcp:tool:search:execute']
console.log(dat.issuer);  // did:idprova:...
```

## Scopes

`Scope` validates and matches permission strings in `namespace:protocol:resource:action` format. Wildcards (`*`) are supported in any position.

```typescript
import { Scope } from '@idprova/core';

// Parse a scope
const s = new Scope('mcp:tool:filesystem:read');
console.log(s.toStringRepr());  // 'mcp:tool:filesystem:read'

// Wildcard coverage check
const broad = new Scope('mcp:tool:*:*');
const narrow = new Scope('mcp:tool:filesystem:read');
console.log(broad.covers(narrow));   // true
console.log(narrow.covers(broad));   // false

// Exact match
const s1 = new Scope('mcp:tool:filesystem:read');
const s2 = new Scope('mcp:tool:filesystem:read');
console.log(s1.covers(s2));  // true

// Invalid scope throws
try {
  new Scope('invalid');  // missing parts
} catch (e) {
  console.error(e);
}
```

**Scope grammar:** `namespace:protocol:resource:action` — all four segments required. Use `*` for wildcard segments.

## Trust Levels

```typescript
import { TrustLevel } from '@idprova/core';

const l0 = new TrustLevel('L0');  // Self-attested (default)
const l1 = new TrustLevel('L1');  // Operator-attested
const l2 = new TrustLevel('L2');  // CA-signed certificate
const l3 = new TrustLevel('L3');  // Multi-party attestation
const l4 = new TrustLevel('L4');  // Hardware-attested (TPM/TEE)

console.log(l0.description);           // human-readable label
console.log(l0.toStringRepr());        // 'L0'

console.log(l0.meetsMinimum(l1));   // false
console.log(l4.meetsMinimum(l1));   // true

// Invalid level throws
try {
  new TrustLevel('L5');
} catch (e) {
  // 'Invalid trust level'
}
```

## Receipt Log

`ReceiptLog` provides an append-only, hash-chained audit trail.

```typescript
import { ReceiptLog } from '@idprova/core';

const log = new ReceiptLog();
console.log(log.length);        // 0
console.log(log.lastHash);      // 'genesis'
console.log(log.nextSequence);  // 0

// Append a receipt entry (hash-chained, signed)
log.append(
  'did:idprova:example.com:my-agent',  // agentDid
  dat.jti,                              // datJti
  'tool_call',                          // actionType
  '{"query": "search term"}',           // inputData
  kp,                                   // signingKey
  'api.example.com',                    // server (optional)
  'search',                             // tool (optional)
  '{"results": []}',                    // outputData (optional)
  'success',                            // status (optional)
  42,                                   // durationMs (optional)
);

// Verify chain integrity (throws on tampering)
log.verifyIntegrity();

console.log(log.nextSequence);  // 1
console.log(log.lastHash);      // blake3 hash of the receipt
```

## Error Handling

All IDProva errors are thrown as standard JavaScript `Error` objects. Check `error.message` for the pattern:

| Condition | Message pattern |
|-----------|----------------|
| Expired DAT | `DatExpiredError` |
| Algorithm confusion | `unsupported algorithm` |
| Invalid trust level | `Invalid trust level` |
| Invalid scope | parse error message |
| Bad secret key bytes | `32 bytes` |
| AID validation failure | validation error message |

```typescript
import { DAT, KeyPair } from '@idprova/core';

const kp = KeyPair.generate();
const dat = DAT.issue('did:idprova:a:b', 'did:idprova:a:c', ['*:*:*:*'], -1, kp);

try {
  dat.validateTiming();
} catch (e) {
  console.error((e as Error).message);  // DatExpiredError: token expired at ...
}
```

### Security: Algorithm Confusion

`DAT.fromCompact()` rejects tokens where `alg` is not `EdDSA`. This prevents algorithm substitution attacks (SEC-3 in the threat model):

```typescript
// A crafted token with alg: "none" is rejected immediately
const malicious = `${badHeader}.${payload}.${sig}`;
try {
  DAT.fromCompact(malicious);
} catch (e) {
  // 'unsupported algorithm: none'
}
```

## Complete Example

```typescript
/**
 * End-to-end example: create two agents, issue a scoped DAT,
 * verify it, check scopes, and inspect the receipt log.
 */
import { AgentIdentity, DAT, Scope, ReceiptLog } from '@idprova/core';

// --- Issuer (orchestrator) ---
const orchestrator = AgentIdentity.create('orchestrator', 'example.com');
console.log(`Orchestrator: ${orchestrator.did}`);

// --- Subject (worker agent) ---
const worker = AgentIdentity.create('worker', 'example.com');
console.log(`Worker:       ${worker.did}`);

// --- Issue a scoped DAT ---
const dat = orchestrator.issueDat(
  worker.did,
  ['mcp:tool:filesystem:read', 'mcp:tool:filesystem:write'],
  3600,
);
const compact = dat.toCompact();
console.log(`DAT (compact): ${compact.slice(0, 60)}...`);

// --- Worker receives and verifies the DAT ---
const receivedDat = DAT.fromCompact(compact);
receivedDat.validateTiming();

const isValid = receivedDat.verifySignature(orchestrator.publicKeyBytes);
if (!isValid) throw new Error('DAT signature invalid');

// --- Check if granted scope covers the required action ---
const granted = receivedDat.scope.map(s => new Scope(s));
const required = new Scope('mcp:tool:filesystem:read');
const hasPermission = granted.some(g => g.covers(required));
if (!hasPermission) throw new Error('missing required scope');

console.log('All checks passed — worker authorised to call mcp:tool:filesystem:read');

// --- Audit log ---
const log = new ReceiptLog();
log.verifyIntegrity();
console.log(`Receipt log entries: ${log.length}`);
```

## Testing

The SDK ships with Vitest tests covering all classes:

```bash
cd sdks/typescript/packages/core
npm test
```

Run a specific suite:

```bash
npm test -- --reporter=verbose
```

## API Reference Summary

| Class | Key methods / properties |
|-------|--------------------------|
| `KeyPair` | `.generate()`, `.fromSecretBytes(b)`, `.sign(msg)`, `.verify(msg, sig)`, `.publicKeyBytes`, `.publicKeyMultibase` |
| `AID` / `Aid` | `.fromJson(s)`, `.toJson()`, `.validate()`, `.did`, `.controller`, `.trustLevel` |
| `AIDBuilder` / `AidBuilder` | `new AIDBuilder()`, `.setId()`, `.setController()`, `.setName()`, `.setTrustLevel()`, `.addEd25519Key()`, `.build()` |
| `DAT` / `Dat` | `.issue(...)`, `.fromCompact(s)`, `.toCompact()`, `.verify(pub, scope?, ctx?)`, `.verifySignature(b)`, `.validateTiming()`, `.isExpired`, `.scope`, `.issuer`, `.subject`, `.jti`, `.expiresAt` |
| `EvaluationContext` | `.actions_in_window`, `.request_ip`, `.agent_trust_level`, `.delegation_depth`, `.country_code`, `.agent_config_hash` |
| `Scope` | `new Scope(s)`, `.covers(other)`, `.toStringRepr()` |
| `TrustLevel` | `new TrustLevel(s)`, `.meetsMinimum(other)`, `.description`, `.toStringRepr()` |
| `ReceiptLog` | `new ReceiptLog()`, `.append(...)`, `.verifyIntegrity()`, `.toJson()`, `.lastHash`, `.nextSequence`, `.length` |
| `AgentIdentity` | `.create(name, domain?)`, `.save(path?)`, `.load(path)`, `.did`, `.aid()`, `.keypair()`, `.issueDat(...)`, `.publicKeyBytes` |

> **Type aliases:** `AID` is exported as an alias for `Aid`, and `AIDBuilder` for `AidBuilder`, for consistency with the Python SDK naming.

## See Also

- [Core Library API Reference](core-api.md)
- [Protocol Concepts](concepts.md)
- [Getting Started (CLI)](getting-started.md)
- [Python SDK Quick-Start](sdk-python.md)
