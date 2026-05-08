/**
 * IDProva — TypeScript quickstart
 *
 * Demonstrates the three primitives:
 *   1. AID — Agent Identity (W3C DID + Ed25519 key)
 *   2. DAT — Delegation Attestation Token (scoped, time-bounded permission grant)
 *   3. Receipt Log — tamper-evident audit chain
 *
 * Run:  npm run quickstart
 */

import {
  KeyPair,
  AgentIdentity,
  DAT,
  AID,
  ReceiptLog,
} from '@idprova/core';

// -----------------------------------------------------------------------------
// 1. Generate a key pair (Ed25519)
// -----------------------------------------------------------------------------
const operatorKeys = KeyPair.generate();

console.log('1. Generated KeyPair');
console.log('   public key (multibase):', operatorKeys.publicKeyMultibase);
console.log();

// -----------------------------------------------------------------------------
// 2. Build an Agent Identity
//
// `AgentIdentity.create()` is the high-level convenience: it generates a fresh
// keypair under the hood and constructs a W3C DID Document for you.
// For full control, use AIDBuilder instead.
// -----------------------------------------------------------------------------
const myAgent = AgentIdentity.create('my-agent', 'example.com');
const aid = myAgent.aid();

console.log('2. Built Agent Identity');
console.log('   DID:        ', aid.did);
console.log('   Controller: ', aid.controller);
console.log('   Trust Level:', aid.trustLevel);
console.log();

// AIDs serialise as JSON DID Documents.
const aidJson = aid.toJson();
const aidRoundtripped = AID.fromJson(aidJson);
console.assert(aidRoundtripped.did === aid.did, 'AID round-trip failed');

// -----------------------------------------------------------------------------
// 3. Issue a Delegation Attestation Token (DAT)
//
// "I, my-agent, delegate to sub-agent the right to read and list MCP tools
//  for the next hour." — signed and verifiable, no central authority needed.
// -----------------------------------------------------------------------------
const subAgentDid = 'did:idprova:example.com:sub-agent';
const dat = myAgent.issueDat(
  subAgentDid,
  ['mcp:tool:read', 'mcp:tool:list'],
  3600, // expires in 1 hour
);

console.log('3. Issued Delegation Token (DAT)');
console.log('   Issuer: ', dat.issuer);
console.log('   Subject:', dat.subject);
console.log('   Scope:  ', dat.scope);
console.log('   TTL:     ', dat.expiresAt - Math.floor(Date.now() / 1000), 'seconds');
console.log();

// DATs are compact JWS strings — they fit in HTTP headers.
const compact = dat.toCompact();
console.log('   Compact form:', compact.slice(0, 60) + '... (' + compact.length + ' chars)');
console.log();

// Anyone with the issuer's public key can verify the DAT.
const sigOk = dat.verifySignature(myAgent.keypair().publicKeyBytes);
console.log('4. DAT signature verifies:', sigOk);

// And anyone can reconstruct it from the compact form.
const parsedDat = DAT.fromCompact(compact);
console.assert(parsedDat.subject === subAgentDid, 'DAT round-trip failed');
console.log();

// -----------------------------------------------------------------------------
// 4. Receipt Log — append-only, hash-chained audit trail
//
// Every action a delegated agent takes can be logged here. Tamper with any
// entry and `verifyIntegrity()` will throw.
// -----------------------------------------------------------------------------
const log = new ReceiptLog();
console.log('5. Receipt log started — entries:', log.length);
log.verifyIntegrity(); // empty log verifies trivially
console.log('   Genesis hash:', log.lastHash);
console.log();

console.log('Quickstart complete.');
console.log();
console.log('Next: see mcp-protected.ts for a request-time enforcement example.');
