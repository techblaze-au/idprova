# DESIGN — Pillar B: `idprova-trust-registry`

**Author:** Claude (orchestrator/design) · **Builder:** GLM (z.ai) · **Date:** 2026-06-25  
**Status:** DESIGN-ONLY (skeleton + `todo!()`). `cargo check` clean.

## 1. Mission & Positioning

The neutral, vendor-neutral, chain-agnostic **Issuer Trust Registry + cross-standard resolver**. It answers the verified whitespace: *"no vendor-neutral, multi-operator agent registry exists"* (Visa's directory is Visa's; Cloudflare's is Cloudflare/IETF; Microsoft's is the Entra tenant). It also answers the TU Berlin unsolved governance gap: *"how trustworthy issuers are determined and their DIDs shared among security domains."*

**Two jobs:**
1. **Issuer trust authority** — a curated, signed, offline-verifiable list of *who may attest to / vouch for an agent* (sovereign/air-gapped friendly).
2. **Cross-standard resolver** — resolve one agent across Web Bot Auth keyid, AP2 issuer DID, MCP OAuth client_id, Entra agent object, all → a canonical `did:aid:`.

**Boundary:** `idprova-registry` manages AID lifecycle/revocation. `idprova-trust-registry` manages *issuer trust governance*. They are distinct.

## 2. Standards & Anchors (verified 2026-06-25)

- **ETSI TS 119 612 / EU LOTL** spirit: curated, signed authority lists, re-cast for agent issuers, `did:aid:`-native.
- **Certificate Transparency (RFC 6962)** spirit: append-only logs, Signed Tree Heads (STH), Merkle consistency proofs.
- **RFC 8785** JSON Canonicalization Scheme (JCS) for deterministic signing.
- **Sovereign mode:** the signed TrustList must verify fully offline (no network, no chain).

## 3. Architecture: Curated TrustList

### 3.1 Data Model

- `Issuer { did, name, jurisdiction, status: IssuerStatus, trust_level: TrustLevel, credential_types: Vec<String>, valid_from, valid_until }`
- `TrustList { version, sequence, issued_at, entries: Vec<Issuer>, proof: Option<Proof> }`
- `SignedTrustList { list, signature, signer_keyid }`

### 3.2 JSON Example (Canonicalized)

```json
{
  "version": "1.0",
  "sequence": 42,
  "issued_at": "2026-06-25T10:00:00Z",
  "entries": [
    {
      "did": "did:aid:z9X...abc",
      "name": "Acme Corp Agent Attestation Authority",
      "jurisdiction": "US",
      "status": "Active",
      "trust_level": "L3",
      "credential_types": ["AgentAttestation", "OrgVerification"],
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z"
    }
  ]
}
```

### 3.3 Signature Flow

1. `TrustAuthority::publish(&self, store: &dyn TrustStore)` queries the active issuers.
2. Entries are sorted deterministically (e.g., by DID string) to ensure canonical representation.
3. The `TrustList` is serialized using **RFC 8785 JCS** (`serde_json_canonicalizer`).
4. The canonical byte string is signed with Ed25519 (`signing_key`).
5. The signature and the `signer_keyid` (identifying the public key in the AID) are attached to form `SignedTrustList`.
6. `verify_signed_list(list, key)` re-canonicalizes the `list` and verifies the Ed25519 signature.

## 4. FEDERATION-SPEC (Append-Only Trust Log)

*This section specifies the protocol for the decentralized, mirrorable trust log. Implementation is deferred; this round provides skeletons (`todo!()`).*

### 4.1 Goals
Prove neutrality. Any operator can mirror the full trust history without a central gatekeeper. Trust is established via cryptographical proofs, not platform monopoly.

### 4.2 Data Structures
- **Merkle Tree:** Leaves are canonicalized `Issuer` state changes (add, suspend, revoke, update). Hash function: **BLAKE3**.
- **SignedTreeHead (STH):**
  ```json
  {
    "size": 1024,
    "root_hash": "base64_blake3_root",
    "sequence": 42,
    "timestamp": "2026-06-25T10:00:00Z",
    "signature": "ed25519_sig_over_sth_contents"
  }
  ```
- **FederationPeer:** `{ url, pubkey }`

### 4.3 Protocol
1. **Append:** Operator submits a state change to the primary log. The log appends the leaf, recomputes the Merkle root, and issues a new STH signed by the log's key.
2. **Mirror Handshake:**
   - Mirror fetches `GET /federation/sth` from `FederationPeer.url`.
   - Mirror compares `size` and `root_hash` with its local copy.
   - If behind, mirror fetches `GET /federation/entries?from=<local_size>`.
3. **Consistency Proof:** To prove the log hasn't been rewritten, the mirror requests `GET /federation/proof/consistency?old_size=<N>&new_size=<M>`. The primary returns the intermediate Merkle hashes. `verify_consistency(old_sth, new_sth, proof)` verifies the cryptographic linkage.
4. **Inclusion Proof:** (Spec only) Prove a specific `Issuer` is in the log at `size`. Returns path from leaf to root.

### 4.4 Threat Model
- **Split-view attack:** Primary shows different logs to different mirrors. *Mitigation:* Mirrors gossip STHs; mirrors demand consistency proofs.
- **Key compromise:** Primary log key forged. *Mitigation:* Log key is separate from issuer attestation keys; log supports key rotation entries.

## 5. Cross-Standard Resolver

Normalizes external standard references to `did:aid:`.

| External Standard | Envelope / Field | Resolution Path to `did:aid:` |
|-------------------|------------------|-------------------------------|
| **WBA** (Web Bot Auth) | `keyid` in HTTP header | Fetch directory at `directory_url`, match `keyid` to WBA JWKs, map to AID. |
| **AP2** (Agent Protocol 2) | `issuer` DID | Cross-resolve DID via universal resolver or local AID registry. |
| **MCP** (Model Context Protocol) | OAuth `client_id` | Lookup registry mapping OAuth subject to `did:aid`. |
| **Entra** (Microsoft) | Agent Object ID | Query Entra-specific adapter to map to `did:aid`. |

*All outbound lookups use `idprova_core::http::validate_registry_url` for SSRF safety.*

## 6. API Reference (Axum)

- `GET /trust-list`: Returns the `SignedTrustList`. Cacheable.
- `GET /issuers/:did`: Returns a specific `Issuer`.
- `GET /issuers?claim_type=<type>`: Returns issuers allowed to attest to a claim type.
- `POST /resolve`: Accepts `AgentRef`, returns `ResolvedAgent`.
- `GET /healthz`: Liveness check.

## 7. Test Matrix
- `test_publish_and_verify_signed_list`: Publish a list, verify it offline.
- `test_may_attest`: Check `TrustStore::may_attest` logic against credential types.
- `test_resolver_normalize`: Map `WebBotAuthKey` to `DidAid` via mock backend.
- `test_federation_consistency_proof`: (Stubbed) Verify `verify_consistency` logic.
