import { ulid } from 'ulid';
import { createJWS, parseJWS, verifyJWS } from '../crypto/jws';
import type { DatHeader, DatClaims, DatConstraints, ParsedScope } from '../types';
import { scopeSetPermits, parseScope } from './scope';

export interface IssueDatOptions {
  issuerDid: string;
  subjectDid: string;
  scopes: string[];
  expiresInSeconds: number;
  privateKey: Uint8Array;
  constraints?: DatConstraints;
  configAttestation?: string;
}

/** Issue a new DAT as a compact JWS. */
export function issueDat(opts: IssueDatOptions): string {
  const now = Math.floor(Date.now() / 1000);

  const header: DatHeader = {
    alg: 'EdDSA',
    typ: 'idprova-dat+jwt',
    kid: `${opts.issuerDid}#key-ed25519`,
  };

  const claims: DatClaims = {
    iss: opts.issuerDid,
    sub: opts.subjectDid,
    iat: now,
    exp: now + opts.expiresInSeconds,
    nbf: now,
    jti: `dat_${ulid()}`,
    scope: opts.scopes,
    delegationChain: [],
  };

  if (opts.constraints) claims.constraints = opts.constraints;
  if (opts.configAttestation) claims.configAttestation = opts.configAttestation;

  return createJWS(header, claims, opts.privateKey);
}

/** Parse a compact JWS DAT without verifying. */
export function parseDat(compact: string) {
  return parseJWS(compact);
}

export interface VerifyResult {
  valid: boolean;
  checks: VerifyCheck[];
}

export interface VerifyCheck {
  name: string;
  passed: boolean;
  detail: string;
}

/** Verify a DAT offline (signature + timing + optional scope check). */
export function verifyDatOffline(
  compact: string,
  publicKey: Uint8Array,
  requiredScope?: string
): VerifyResult {
  const checks: VerifyCheck[] = [];

  // 1. Parse
  let claims: DatClaims;
  try {
    const parsed = parseJWS(compact);
    claims = parsed.claims;
    checks.push({ name: 'Parse', passed: true, detail: 'Token parsed successfully' });
  } catch (e) {
    checks.push({ name: 'Parse', passed: false, detail: String(e) });
    return { valid: false, checks };
  }

  // 2. Algorithm check (already done in parseJWS, but make it visible)
  checks.push({ name: 'Algorithm', passed: true, detail: 'EdDSA (Ed25519)' });

  // 3. Signature
  const sigValid = verifyJWS(compact, publicKey);
  checks.push({
    name: 'Signature',
    passed: sigValid,
    detail: sigValid ? 'Valid Ed25519 signature' : 'Signature verification failed',
  });

  // 4. Timing
  const now = Math.floor(Date.now() / 1000);
  const notExpired = now < claims.exp;
  checks.push({
    name: 'Expiration',
    passed: notExpired,
    detail: notExpired
      ? `Expires ${new Date(claims.exp * 1000).toISOString()}`
      : `Expired at ${new Date(claims.exp * 1000).toISOString()}`,
  });

  const notBefore = now >= claims.nbf;
  checks.push({
    name: 'Not Before',
    passed: notBefore,
    detail: notBefore
      ? `Valid since ${new Date(claims.nbf * 1000).toISOString()}`
      : `Not valid until ${new Date(claims.nbf * 1000).toISOString()}`,
  });

  // 5. Scope check (if requested)
  if (requiredScope && requiredScope.trim()) {
    try {
      const requested = parseScope(requiredScope);
      const granted = claims.scope;
      const permitted = scopeSetPermits(granted, requested);
      checks.push({
        name: 'Scope',
        passed: permitted,
        detail: permitted
          ? `${requiredScope} is permitted by granted scopes`
          : `${requiredScope} is NOT permitted by granted scopes [${granted.join(', ')}]`,
      });
    } catch (e) {
      checks.push({ name: 'Scope', passed: false, detail: `Invalid scope: ${e}` });
    }
  }

  const valid = checks.every(c => c.passed);
  return { valid, checks };
}
