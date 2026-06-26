# Pillar A: Web Bot Auth Protocol Implementation

**Author:** Claude (orchestrator/design)  
**Date:** 2026-06-25  
**Status:** Design Phase (IMPLEMENTATION PENDING)  
**Component:** `idprova-webbotauth`

## 1. Overview

Pillar A provides the implementation layer for **RFC 9421 (HTTP Message Signatures)** and the **IETF Web Bot Auth (WBA)** architecture.

Its primary goal is to enable IDProva agents to speak the de-facto standard for machine-to-machine HTTP authentication without ceding control of their identity root. Agents present a `Signature-Agent` header pointing to an independent directory, while internally resolving all trust and keys back to the sovereign `did:aid:` document.

## 2. Architecture

### 2.1 Identity Binding

We follow a "speak WBA, trust AID" pattern:

1. **Wire Layer (WBA)**: The agent emits standard HTTP `Signature-Input` and `Signature` headers defined in RFC 9421.
2. **Directory Layer**: The agent serves a JWK Set (JWKS) at a URL advertised in the `Signature-Agent` header.
3. **Trust Layer (AID)**: The `kid` (Key ID) in the signature is the RFC 7638 thumbprint of the JWK. The JWK's public key must match a verification method in the agent's `did:aid:` document.

### 2.2 Cryptography

*   **Algorithm**: `ed25519` (RFC 8032).
*   **Key Format**: OKP (Octet Key Pair) in JWK.
*   **Integrity**: Deterministic signature base construction per RFC 9421 §2.5.

### 2.3 Module Structure

*   **`request`**: Framework-agnostic representation of an HTTP request (`SignableRequest`).
*   **`components`**: Enumerates HTTP message components (`@method`, `@authority`, etc.) and handles the deterministic serialization of the signature base.
*   **`sfv`**: Abstraction over the `sfv` crate for parsing/serializing Structured Fields (Dictionary/Lists).
*   **`signer`**: `HttpSigner` struct that takes a private key and a request, returning the required headers.
*   **`verifier`**: `HttpVerifier` that validates signatures, timestamp freshness, and component coverage.
*   **`directory`**: Structures for `KeyDirectory` (JWKS) and `SignatureAgentCard`.
*   **`binding`**: Logic to bind a JWK thumbprint (`kid`) to a specific verification method in a `did:aid:` document.

## 3. Protocol Details

### 3.1 Signature Base (RFC 9421)

For a standard request, the covered components might be `["@method", "@authority", "@path"]`.
The signature base string is constructed as:

```text
"@method": POST
"@authority": api.example.com
"@path": /foo
"@signature-params": ("@method" "@authority" "@path");created=1618884473;keyid="...";alg="ed25519"
```

**Crucial**: The `@signature-params` line is always last and includes the list of component names (excluding itself). This allows the verifier to deterministically reconstruct the base.

### 3.2 Signature-Agent Header

The `Signature-Agent` header is a Dictionary Structured Field:

```http
Signature-Agent: sig-controller="https://agent.example.com/.well-known/web-bot-auth"
```

The media type for the directory **MUST** be `application/http-message-signatures-directory+json`.

### 3.3 Key Directory (JWKS)

The directory returns a JSON object containing the agent's public keys. The `kid` used in the HTTP signature header must exist in this set.

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "2syT-h5f3yI6XJtFOP3pEBMCk63aD8WkZLHz8Bk1Tqk...",
      "kid": "JWK_thumbprint_Base64URL"
    }
  ]
}
```

## 4. Verification Strategy (Deterministic)

Verification in `idprova-webbotauth` is performed locally ("TU-Berlin anti-pattern fix"). The logic does not make network calls to verify the signature itself.

1.  **Parse Headers**: Extract `Signature-Input` and `Signature`.
2.  **Reconstruct Base**: Using the request components and the `@signature-params` from the input, recreate the exact signature base string.
3.  **Resolve Key**: Look up the `kid` in the provided JWK Set (cached or fetched safely via `validate_registry_url`).
4.  **Verify**: Use `ed25519_dalek` to verify the signature bytes against the base.
5.  **Policy Checks**: 
    *   Ensure `created` <= `now`.
    *   Ensure `expires` > `now` (if present).
    *   Ensure all required components (e.g. `@method`) are present in the covered list.

## 5. Key Binding (WBA to AID)

The binding between the ephemeral/operational Web Bot Auth key and the long-lived `did:aid:` identity is established via the AID Document.

1.  The `SignatureAgentCard` contains the `id` (the `did:aid:`).
2.  The AID document contains a `verificationMethod` entry with the JWK public key.
3.  The `kid` (thumbprint) matches the JWK in the AID.

This ensures that even if the agent rotates its WBA keys (changes the JWKS), the trust anchors back to the DID.

## 6. Test Matrix

| Feature | Test Case | Status |
| :--- | :--- | :--- |
| **Signing** | RFC 9421 Ed25519 Vector (Appendix B) | `#[ignore]` (Placeholder) |
| **Signing** | Custom covered components list + headers | TODO |
| **Verification** | Valid request, accepted | TODO |
| **Verification** | Expired signature (`expires` < `now`) | TODO |
| **Verification** | Missing required component (e.g. no `@method`) | TODO |
| **Verification** | Invalid signature bytes | TODO |
| **Directory** | JWKS serialization matches spec | TODO |
| **Directory** | `Signature-Agent` header serialization | TODO |
| **Binding** | `kid` derivation (JWK Thumbprint) | TODO |
| **Binding** | `kid` -> `did:aid:` resolution | TODO |
