import { sign, verify } from './ed25519';
import { base64urlEncode, base64urlDecode, stringToBytes, bytesToString } from './encoding';
import type { DatHeader, DatClaims } from '../types';

/**
 * Create a compact JWS (header.payload.signature).
 * 
 * CRITICAL: JSON field ordering must match Rust serde output.
 * Header: alg, typ, kid
 * Claims: iss, sub, iat, exp, nbf, jti, scope, constraints?, configAttestation?, delegationChain?
 */
export function createJWS(
  header: DatHeader,
  claims: DatClaims,
  privateKey: Uint8Array
): string {
  // Build header JSON with exact field order matching Rust serde
  const headerJson = JSON.stringify({
    alg: header.alg,
    typ: header.typ,
    kid: header.kid,
  });

  // Build claims JSON with exact field order matching Rust serde
  const claimsObj: Record<string, unknown> = {
    iss: claims.iss,
    sub: claims.sub,
    iat: claims.iat,
    exp: claims.exp,
    nbf: claims.nbf,
    jti: claims.jti,
    scope: claims.scope,
  };
  // Only include optional fields if present (matches serde skip_serializing_if)
  if (claims.constraints !== undefined) {
    claimsObj.constraints = serializeConstraints(claims.constraints);
  }
  if (claims.configAttestation !== undefined) {
    claimsObj.configAttestation = claims.configAttestation;
  }
  if (claims.delegationChain !== undefined) {
    claimsObj.delegationChain = claims.delegationChain;
  }

  const claimsJson = JSON.stringify(claimsObj);

  const headerB64 = base64urlEncode(stringToBytes(headerJson));
  const claimsB64 = base64urlEncode(stringToBytes(claimsJson));
  const signingInput = `${headerB64}.${claimsB64}`;

  const signature = sign(stringToBytes(signingInput), privateKey);
  const sigB64 = base64urlEncode(signature);

  return `${headerB64}.${claimsB64}.${sigB64}`;
}

/** Serialize DatConstraints with exact Rust serde field names (skip_serializing_if = None). */
function serializeConstraints(c: NonNullable<DatClaims['constraints']>): Record<string, unknown> {
  const obj: Record<string, unknown> = {};
  if (c.maxActions !== undefined) obj.maxActions = c.maxActions;
  if (c.allowedServers !== undefined) obj.allowedServers = c.allowedServers;
  if (c.requireReceipt !== undefined) obj.requireReceipt = c.requireReceipt;
  if (c.maxCallsPerHour !== undefined) obj.maxCallsPerHour = c.maxCallsPerHour;
  if (c.maxCallsPerDay !== undefined) obj.maxCallsPerDay = c.maxCallsPerDay;
  if (c.maxConcurrent !== undefined) obj.maxConcurrent = c.maxConcurrent;
  if (c.allowedIPs !== undefined) obj.allowedIPs = c.allowedIPs;
  if (c.deniedIPs !== undefined) obj.deniedIPs = c.deniedIPs;
  if (c.requiredTrustLevel !== undefined) obj.requiredTrustLevel = c.requiredTrustLevel;
  if (c.maxDelegationDepth !== undefined) obj.maxDelegationDepth = c.maxDelegationDepth;
  if (c.geofence !== undefined) obj.geofence = c.geofence;
  if (c.timeWindows !== undefined) obj.timeWindows = c.timeWindows;
  if (c.requiredConfigAttestation !== undefined) obj.requiredConfigAttestation = c.requiredConfigAttestation;
  return obj;
}

/** Parse a compact JWS into its three parts. Does NOT verify signature. */
export function parseJWS(compact: string): {
  header: DatHeader;
  claims: DatClaims;
  signature: Uint8Array;
  rawHeaderB64: string;
  rawClaimsB64: string;
} {
  const parts = compact.split('.');
  if (parts.length !== 3) {
    throw new Error('compact JWS must have 3 parts');
  }

  const [rawHeaderB64, rawClaimsB64, sigB64] = parts;
  const headerBytes = base64urlDecode(rawHeaderB64);
  const claimsBytes = base64urlDecode(rawClaimsB64);
  const signature = base64urlDecode(sigB64);

  const header: DatHeader = JSON.parse(bytesToString(headerBytes));
  if (header.alg !== 'EdDSA') {
    throw new Error(`unsupported algorithm '${header.alg}': only 'EdDSA' is permitted`);
  }

  const claims: DatClaims = JSON.parse(bytesToString(claimsBytes));

  return { header, claims, signature, rawHeaderB64, rawClaimsB64 };
}

/**
 * Verify a compact JWS signature against a public key.
 * Uses original base64url segments per RFC 7515 §5.2 (avoids re-serialization).
 */
export function verifyJWS(compact: string, publicKey: Uint8Array): boolean {
  const { signature, rawHeaderB64, rawClaimsB64 } = parseJWS(compact);
  const signingInput = `${rawHeaderB64}.${rawClaimsB64}`;
  return verify(signature, stringToBytes(signingInput), publicKey);
}
