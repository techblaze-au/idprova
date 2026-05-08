/**
 * IDProva — MCP-protected request handler
 *
 * Demonstrates the policy-enforcement-point pattern: an MCP server (or any
 * HTTP/A2A endpoint) that requires every inbound call to carry a valid
 * IDProva Delegation Attestation Token in its `Authorization: IDProva <jws>`
 * header.
 *
 * The handler:
 *   1. Parses the incoming DAT from the Authorization header
 *   2. Verifies the issuer's signature against the issuer's known public key
 *   3. Validates timing (not expired / not before valid)
 *   4. Checks the requested scope is covered by the granted scope
 *   5. Appends an Action Receipt to the audit log
 *
 * In production, step 2 would resolve the issuer's AID from a registry or
 * via did:web / did:idprova resolution. We hard-code one issuer here for clarity.
 */

import {
  AgentIdentity,
  DAT,
  Scope,
} from '@idprova/core';

// -----------------------------------------------------------------------------
// Server-side state (in production: registry-backed)
// -----------------------------------------------------------------------------

// Pretend this is the issuer registered with our service. In reality you'd
// resolve the DID and pull the verification key from a registry.
const trustedOperator = AgentIdentity.create('alice', 'example.com');
const trustedOperatorDid = trustedOperator.did;
const trustedOperatorPubkey = trustedOperator.keypair().publicKeyBytes;

// Audit trail. v0.1.x ReceiptLog is read-only at the JS layer — to record
// receipts you persist them server-side (file, DB) and verify integrity later.
// v0.2 will expose an append API.

// -----------------------------------------------------------------------------
// The protected handler
// -----------------------------------------------------------------------------
type Request = {
  method: string;          // MCP method, e.g. 'tools/list'
  authorization?: string;  // 'IDProva <compact-jws>'
  agentDid: string;        // who is calling (for audit)
};

type Response = {
  ok: boolean;
  status: number;
  body: string;
};

function requiredScopeFor(method: string): string {
  // Map MCP methods to required IDProva scopes.
  // Keep this declarative — it's the auth policy of your service.
  if (method.startsWith('tools/list')) return 'mcp:tool:list';
  if (method.startsWith('tools/call')) return 'mcp:tool:execute';
  if (method.startsWith('resources/read')) return 'mcp:resource:read';
  return 'mcp:default';
}

function handle(req: Request): Response {
  // 1. Parse the Authorization header
  if (!req.authorization?.startsWith('IDProva ')) {
    return { ok: false, status: 401, body: 'missing IDProva authorization' };
  }
  const compact = req.authorization.slice('IDProva '.length);

  let dat;
  try {
    dat = DAT.fromCompact(compact);
  } catch (e) {
    return { ok: false, status: 401, body: `malformed DAT: ${(e as Error).message}` };
  }

  // 2. Verify signature against the issuer's known public key
  if (dat.issuer !== trustedOperatorDid) {
    return { ok: false, status: 401, body: `unknown issuer ${dat.issuer}` };
  }
  if (!dat.verifySignature(trustedOperatorPubkey)) {
    return { ok: false, status: 401, body: 'DAT signature does not verify' };
  }

  // 3. Validate timing
  try {
    dat.validateTiming();
  } catch (e) {
    return { ok: false, status: 401, body: `DAT timing: ${(e as Error).message}` };
  }

  // 4. Check scope coverage
  const required = new Scope(requiredScopeFor(req.method));
  const covered = dat.scope.some((s) => new Scope(s).covers(required));
  if (!covered) {
    return {
      ok: false,
      status: 403,
      body: `DAT scope ${JSON.stringify(dat.scope)} does not cover required ${required.toStringRepr()}`,
    };
  }

  // 5. Audit-log the action (in production: persist this somewhere durable)
  console.log(
    `[audit] ${dat.subject} performed ${req.method} (delegated by ${dat.issuer}, jti=${dat.jti})`,
  );

  return { ok: true, status: 200, body: `${req.method} OK` };
}

// -----------------------------------------------------------------------------
// Demo — exercise the handler with a valid and an expired DAT
// -----------------------------------------------------------------------------
const subAgent = 'did:idprova:example.com:sub-agent';

// Valid DAT: 1 hour TTL, scope covers tools/list
const validDat = trustedOperator.issueDat(subAgent, ['mcp:tool:list'], 3600);

// Expired DAT: signed by the trusted operator but with -1 second TTL
const expiredDat = DAT.issue(
  trustedOperatorDid,
  subAgent,
  ['mcp:tool:list'],
  -1,
  trustedOperator.keypair(),
);

// Insufficient-scope DAT: only allows reading resources, but caller wants to list tools
const limitedDat = trustedOperator.issueDat(
  subAgent,
  ['mcp:resource:read'],
  3600,
);

// Wrong-issuer DAT: signed by some random key, not our trusted operator
const stranger = AgentIdentity.create('mallory', 'attacker.example');
const wrongIssuerDat = stranger.issueDat(subAgent, ['mcp:*:*'], 3600);

console.log('--- valid DAT ---');
console.log(handle({
  method: 'tools/list',
  authorization: 'IDProva ' + validDat.toCompact(),
  agentDid: subAgent,
}));

console.log('\n--- expired DAT ---');
console.log(handle({
  method: 'tools/list',
  authorization: 'IDProva ' + expiredDat.toCompact(),
  agentDid: subAgent,
}));

console.log('\n--- insufficient scope ---');
console.log(handle({
  method: 'tools/list',
  authorization: 'IDProva ' + limitedDat.toCompact(),
  agentDid: subAgent,
}));

console.log('\n--- unknown issuer ---');
console.log(handle({
  method: 'tools/list',
  authorization: 'IDProva ' + wrongIssuerDat.toCompact(),
  agentDid: subAgent,
}));

console.log('\n--- missing authorization ---');
console.log(handle({
  method: 'tools/list',
  agentDid: subAgent,
}));
