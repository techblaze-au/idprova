# Compliance Mapping

How IDProva protocol controls map to NIST SP 800-207 (Zero Trust Architecture) and the Australian ISM (Information Security Manual).

---

## NIST SP 800-207 — Zero Trust Architecture

| NIST ZTA Tenet | IDProva Control | Implementation |
|----------------|-----------------|----------------|
| **1. All data sources and computing services are considered resources** | Agent Identity Documents (AIDs) | Every AI agent is a distinct identity with its own DID and Ed25519 key pair |
| **2. All communication is secured regardless of network location** | DAT verification pipeline | All inter-agent actions require a valid, signed DAT — no implicit trust based on network |
| **3. Access to individual enterprise resources is granted on a per-session basis** | Short-lived DATs with constraints | DATs carry `exp` (expiry), rate limits, delegation depth limits, IP allowlists, geofencing |
| **4. Access is determined by dynamic policy** | Constraint engine + PolicyEvaluator | Runtime context (IP, trust level, action count, config hash) evaluated against DAT constraints at verification time |
| **5. The enterprise monitors and measures integrity and security posture** | Hash-chained receipt log | Every agent action produces a cryptographic receipt; chain integrity is independently verifiable |
| **6. All resource authentication and authorization are dynamic** | Real-time DAT verification + revocation | `/v1/dat/verify` checks revocation status, constraint satisfaction, and scope grants in real time |
| **7. The enterprise collects as much information as possible about assets** | AID registry + receipt log | Full audit trail: who issued what delegation, what actions were taken, chain of custody |

### ZTA Component Mapping

| ZTA Component | IDProva Equivalent |
|---------------|-------------------|
| Policy Engine (PE) | DAT constraint engine (`dat::constraints`, `policy::evaluator`) |
| Policy Administrator (PA) | DAT issuer (operator signing DATs with scoped permissions) |
| Policy Enforcement Point (PEP) | `idprova-verify` crate / `/v1/dat/verify` endpoint |
| Identity Provider | AID registry (`/v1/aid/:id`) |
| SIEM / Logging | Receipt log with hash-chain integrity verification |

---

## Australian ISM Controls

Selected controls from the ISM (updated March 2025) relevant to AI agent identity and delegation.

### Access Control

| ISM Control | IDProva Mapping |
|-------------|-----------------|
| **ISM-0432** Requests for access are validated before granting access | DAT verification pipeline: signature → timing → scope → constraints |
| **ISM-1503** Standard users are not granted privileged access | DAT scopes enforce least-privilege: agents only get the scopes explicitly granted |
| **ISM-1507** Privileged access is limited to what is required | 4-part scope grammar (`namespace:protocol:resource:action`) enables fine-grained delegation |
| **ISM-1508** Privileged access events are logged | Receipt log captures every delegated action with cryptographic chain |
| **ISM-0585** System access is removed or suspended on same day for personnel no longer requiring access | DAT revocation (`/v1/dat/revoke`) is immediate; verification checks revocation before any crypto |

### Cryptographic Controls

| ISM Control | IDProva Mapping |
|-------------|-----------------|
| **ISM-0457** Only approved cryptographic algorithms are used | Ed25519 (EdDSA) only; `verify_algorithm()` hard-rejects non-EdDSA tokens |
| **ISM-0462** Cryptographic key management processes cover the whole lifecycle | AID key registration → DAT signing → revocation → key rotation (via AID update) |
| **ISM-0467** Private keys are protected from unauthorised access | Key material never leaves the signing party; DATs carry only public key references |

### Logging & Accountability

| ISM Control | IDProva Mapping |
|-------------|-----------------|
| **ISM-0580** Events are logged for actions performed by users | Receipt log: every agent action produces a signed, timestamped receipt |
| **ISM-0585** Event logs are protected from unauthorised modification | Hash-chain integrity: each receipt includes the BLAKE3 hash of the previous receipt |
| **ISM-1405** An event logging facility is operated | `verify_receipt_log()` independently verifies chain integrity; any tamper breaks the chain |

### Network Security

| ISM Control | IDProva Mapping |
|-------------|-----------------|
| **ISM-1416** Network traffic is encrypted | HTTPS/TLS for registry API; DAT tokens are self-contained JWS (verifiable offline) |
| **ISM-0529** Rate limiting is applied | 120 req/60s per IP on the registry; DAT-level rate limits via `rate_limit` constraint |

---

## Scope Grammar & Least Privilege

IDProva enforces least privilege through its 4-part scope grammar:

```
namespace:protocol:resource:action
```

Examples:
- `mcp:tool:filesystem:read` — MCP tool, filesystem resource, read-only
- `a2a:agent:default:invoke` — A2A agent invocation
- `mcp:*:*:*` — wildcard (full MCP access)

Wildcards (`*`) are supported at each level, enabling graduated privilege escalation that maps directly to ISM-1507 (limit privileged access to what is required).

---

## Delegation Chain Security

DATs support constrained delegation:

1. **Max delegation depth** — prevents unbounded re-delegation chains
2. **Scope narrowing** — child DATs cannot exceed parent scope
3. **Config attestation** — optional binding to a specific agent configuration hash
4. **Geofencing** — restrict delegation to specific country codes
5. **Time windows** — constrain when delegated access is valid

This maps to NIST ZTA tenet 3 (per-session access) and ISM-0432 (validate before granting).
