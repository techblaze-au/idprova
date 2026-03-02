import { describe, it, expect } from 'vitest';
import {
  KeyPair,
  AID,
  AIDBuilder,
  DAT,
  Scope,
  TrustLevel,
  ReceiptLog,
  AgentIdentity,
} from '../index.js';

describe('KeyPair', () => {
  it('generates a key pair', () => {
    const kp = KeyPair.generate();
    expect(kp.publicKeyBytes.length).toBe(32);
    expect(kp.publicKeyMultibase.startsWith('z')).toBe(true);
  });

  it('signs and verifies', () => {
    const kp = KeyPair.generate();
    const message = Buffer.from('hello idprova');
    const sig = kp.sign(message);
    expect(kp.verify(message, sig)).toBe(true);
  });

  it('fails verification with wrong key', () => {
    const kp1 = KeyPair.generate();
    const kp2 = KeyPair.generate();
    const sig = kp1.sign(Buffer.from('hello'));
    expect(kp2.verify(Buffer.from('hello'), sig)).toBe(false);
  });

  it('rejects invalid secret bytes', () => {
    expect(() => KeyPair.fromSecretBytes(Buffer.from('too short'))).toThrow('32 bytes');
  });
});

describe('AgentIdentity', () => {
  it('creates with default domain', () => {
    const identity = AgentIdentity.create('test-agent');
    expect(identity.did).toBe('did:idprova:local.dev:test-agent');
  });

  it('creates with custom domain', () => {
    const identity = AgentIdentity.create('kai', 'techblaze.com.au');
    expect(identity.did).toBe('did:idprova:techblaze.com.au:kai');
  });

  it('returns AID document', () => {
    const identity = AgentIdentity.create('test', 'example.com');
    const aid = identity.aid();
    expect(aid.did).toBe('did:idprova:example.com:test');
    expect(aid.trustLevel).toBe('L0');
  });

  it('AID roundtrips through JSON', () => {
    const identity = AgentIdentity.create('test', 'example.com');
    const aid = identity.aid();
    const json = aid.toJson();
    const parsed = JSON.parse(json);
    expect(parsed.id).toBe('did:idprova:example.com:test');

    const aid2 = AID.fromJson(json);
    expect(aid2.did).toBe(aid.did);
  });

  it('issues a DAT', () => {
    const issuer = AgentIdentity.create('alice', 'example.com');
    const dat = issuer.issueDat(
      'did:idprova:example.com:agent',
      ['mcp:tool:read'],
      3600,
    );
    expect(dat.issuer).toBe('did:idprova:example.com:alice');
    expect(dat.subject).toBe('did:idprova:example.com:agent');
    expect(dat.isExpired).toBe(false);
  });
});

describe('DAT', () => {
  it('issues and verifies', () => {
    const kp = KeyPair.generate();
    const dat = DAT.issue(
      'did:idprova:example.com:alice',
      'did:idprova:example.com:agent',
      ['mcp:tool:read'],
      3600,
      kp,
    );
    expect(dat.verifySignature(kp.publicKeyBytes)).toBe(true);
  });

  it('roundtrips through compact JWS', () => {
    const kp = KeyPair.generate();
    const dat = DAT.issue(
      'did:idprova:example.com:alice',
      'did:idprova:example.com:agent',
      ['mcp:tool:read', 'mcp:tool:write'],
      3600,
      kp,
    );
    const compact = dat.toCompact();
    const parsed = DAT.fromCompact(compact);
    expect(parsed.issuer).toBe(dat.issuer);
    expect(parsed.subject).toBe(dat.subject);
    expect(parsed.scope).toEqual(dat.scope);
  });

  it('detects expired DAT', () => {
    const kp = KeyPair.generate();
    const dat = DAT.issue(
      'did:idprova:example.com:alice',
      'did:idprova:example.com:agent',
      ['mcp:tool:read'],
      -1, // Already expired
      kp,
    );
    expect(dat.isExpired).toBe(true);
    expect(() => dat.validateTiming()).toThrow('DatExpiredError');
  });

  it('fails verification with wrong key', () => {
    const kp1 = KeyPair.generate();
    const kp2 = KeyPair.generate();
    const dat = DAT.issue(
      'did:idprova:example.com:alice',
      'did:idprova:example.com:agent',
      ['mcp:tool:read'],
      3600,
      kp1,
    );
    expect(dat.verifySignature(kp2.publicKeyBytes)).toBe(false);
  });

  it('supports constraints', () => {
    const kp = KeyPair.generate();
    const dat = DAT.issue(
      'did:idprova:example.com:alice',
      'did:idprova:example.com:agent',
      ['mcp:tool:read'],
      3600,
      kp,
      100,  // maxActions
      true, // requireReceipt
    );
    expect(dat.jti.startsWith('dat_')).toBe(true);
  });

  it('rejects algorithm confusion (SEC-3)', () => {
    // Craft a JWS with alg: "none"
    const header = Buffer.from('{"alg":"none","typ":"idprova-dat+jwt","kid":"test"}')
      .toString('base64url');
    const payload = Buffer.from('{"iss":"a","sub":"b","iat":0,"exp":999999999999,"nbf":0,"jti":"x","scope":[]}')
      .toString('base64url');
    const sig = Buffer.from('fake').toString('base64url');
    const compact = `${header}.${payload}.${sig}`;
    expect(() => DAT.fromCompact(compact)).toThrow('unsupported algorithm');
  });
});

describe('Scope', () => {
  it('parses a scope', () => {
    const s = new Scope('mcp:tool:read');
    expect(s.toStringRepr()).toBe('mcp:tool:read');
  });

  it('checks coverage with wildcard', () => {
    const broad = new Scope('mcp:*:*');
    const narrow = new Scope('mcp:tool:read');
    expect(broad.covers(narrow)).toBe(true);
    expect(narrow.covers(broad)).toBe(false);
  });

  it('checks exact match', () => {
    const s1 = new Scope('mcp:tool:read');
    const s2 = new Scope('mcp:tool:read');
    expect(s1.covers(s2)).toBe(true);
  });

  it('rejects invalid scope', () => {
    expect(() => new Scope('invalid')).toThrow();
  });
});

describe('TrustLevel', () => {
  it('parses and compares levels', () => {
    const l0 = new TrustLevel('L0');
    const l1 = new TrustLevel('L1');
    const l4 = new TrustLevel('L4');
    expect(l0.meetsMinimum(l0)).toBe(true);
    expect(l0.meetsMinimum(l1)).toBe(false);
    expect(l4.meetsMinimum(l1)).toBe(true);
  });

  it('has description', () => {
    const l0 = new TrustLevel('L0');
    expect(l0.description.length).toBeGreaterThan(0);
  });

  it('rejects invalid level', () => {
    expect(() => new TrustLevel('L5')).toThrow('Invalid trust level');
  });
});

describe('ReceiptLog', () => {
  it('creates empty log', () => {
    const log = new ReceiptLog();
    expect(log.length).toBe(0);
    expect(log.lastHash).toBe('genesis');
    expect(log.nextSequence).toBe(0);
  });

  it('verifies empty log', () => {
    const log = new ReceiptLog();
    expect(() => log.verifyIntegrity()).not.toThrow();
  });
});
