import { toMultibase } from '../crypto/encoding';
import type { AidDocument, VerificationMethod, AidService, AgentMetadata } from '../types';

export interface BuildAidOptions {
  did: string;
  controllerDid: string;
  name: string;
  publicKey: Uint8Array;
  description?: string;
  model?: string;
  runtime?: string;
  configAttestation?: string;
  trustLevel?: string;
}

/** Build an AID document matching Rust AidBuilder output. */
export function buildAidDocument(opts: BuildAidOptions): AidDocument {
  const now = new Date().toISOString();
  const multibase = toMultibase(opts.publicKey);

  const vm: VerificationMethod = {
    id: '#key-ed25519',
    type: 'Ed25519VerificationKey2020',
    controller: opts.controllerDid,
    publicKeyMultibase: multibase,
  };

  const metadata: AgentMetadata = {
    name: opts.name,
  };
  if (opts.description) metadata.description = opts.description;
  if (opts.model) metadata.model = opts.model;
  if (opts.runtime) metadata.runtime = opts.runtime;
  if (opts.configAttestation) metadata.configAttestation = opts.configAttestation;

  const service: AidService = {
    id: '#idprova-metadata',
    type: 'IdprovaAgentMetadata',
    serviceEndpoint: metadata,
  };

  const doc: AidDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://idprova.dev/v1',
    ],
    id: opts.did,
    controller: opts.controllerDid,
    verificationMethod: [vm],
    authentication: ['#key-ed25519'],
    service: [service],
    version: 1,
    created: now,
    updated: now,
  };

  if (opts.trustLevel) doc.trustLevel = opts.trustLevel;

  return doc;
}

/** Validate basic AID document structure. */
export function validateAidDocument(doc: AidDocument): string[] {
  const errors: string[] = [];

  if (!doc.id || !doc.id.startsWith('did:aid:')) {
    errors.push('id must start with did:aid:');
  }

  // Validate DID format: did:aid:{domain}:{name}
  const parts = doc.id.split(':');
  if (parts.length !== 4) {
    errors.push('id must have format did:aid:{domain}:{name}');
  } else {
    if (!parts[2].includes('.')) errors.push('domain must contain a dot');
    if (!/^[a-z0-9-]+$/.test(parts[3])) errors.push('local name must be lowercase alphanumeric with hyphens');
  }

  if (!doc.controller || !doc.controller.startsWith('did:')) {
    errors.push('controller must be a valid DID');
  }

  if (!doc.verificationMethod || doc.verificationMethod.length === 0) {
    errors.push('at least one verification method required');
  }

  if (doc.authentication) {
    for (const ref of doc.authentication) {
      const found = doc.verificationMethod?.some(vm => vm.id === ref);
      if (!found) errors.push(`authentication reference ${ref} not found in verification methods`);
    }
  }

  return errors;
}
