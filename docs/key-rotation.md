# Key Rotation Playbook

**Status:** v0.1 — operator playbook
**Audience:** developers and operators integrating IDprova
**Supersedes:** scattered references in `protocol-spec-v0.1.md` §3.4.3, §4.4.3, §4.4.4
**See also:** [security.md](security.md) · [STRIDE-THREAT-MODEL.md](STRIDE-THREAT-MODEL.md) §2.2

---

## TL;DR

- **Rotate Ed25519 signing keys at least every 90 days.** ML-DSA-65 keys at least every 180 days.
- **Rotate immediately if you suspect compromise.** Don't wait for the schedule.
- **Existing DATs and receipts remain valid** through rotation until their natural expiry — rotation is non-disruptive.
- **Revocation is different from rotation.** Rotation replaces a key going forward; revocation invalidates a specific DAT or removes a specific key from a DID Document. Use both.

---

## 1. Why rotate

Three reasons, in order of likelihood:

1. **Reduce blast radius of an undetected compromise.** If an attacker has been quietly using a stolen key, scheduled rotation forces them to either re-compromise or stop. The shorter the rotation interval, the smaller the window in which a stolen key has value.
2. **Limit the lifetime of cryptographic exposure.** Modern key compromise doesn't require ECDLP breaks — side-channel leaks, supply chain attacks, and operator mistakes are more common. Routine rotation is hygiene.
3. **Prepare the operational muscle for emergency rotation.** When an actual compromise is detected, rotation needs to happen in minutes, not days. Practising it routinely is the only way to keep the playbook current.

---

## 2. When to rotate

| Trigger | Action | SLA |
|---|---|---|
| Scheduled (Ed25519) | Routine rotation | At least every 90 days |
| Scheduled (ML-DSA-65) | Routine rotation | At least every 180 days |
| Suspected compromise | Emergency rotation + revocation of in-flight DATs signed by the suspect key | Within 1 hour of detection |
| Confirmed compromise | Emergency rotation + revoke ALL DATs signed by the compromised key + investigate | Within 15 minutes |
| Personnel change (key custodian leaves) | Routine rotation | Within 24 hours of departure |
| Trust level transition (L1 → L2) | Re-attestation may include new key | At time of trust elevation |
| Algorithm migration (Ed25519 → ML-DSA-65) | Multi-step rotation with both algorithms in document | Per migration plan |

Compromise indicators:
- Anomalous receipt patterns from the agent (unusual time of day, unusual targets, unusual frequency)
- Receipt log integrity check fails (`ReceiptLog::verify_integrity()` returns false)
- Unexpected DATs issued from the agent's signing key
- Out-of-band signal (SOC alert, customer report, threat intel)
- Disclosed dependency vulnerability in the runtime that handled the key

---

## 3. How to rotate (the protocol-level flow)

Key rotation is performed by **updating the DID Document** to add the new key, then later removing the old key. Both keys coexist during the transition window.

### Step-by-step

```
Step 1: Generate new key locally
        └── KeyPair.generate() (or your KMS equivalent)

Step 2: Build updated DID Document
        ├── Keep existing verificationMethod entries (old key)
        ├── Add new verificationMethod entry (new key, fresh kid)
        └── Update authentication / assertionMethod arrays to include new key

Step 3: Sign the update with the OLD key
        └── proof.proofValue = oldKey.sign(canonical(updated_document))
            ※ This is the continuity guarantee — only the legitimate
              key holder can authorise a key change.

Step 4: Submit update to registry
        └── PUT /v1/aid/{did}    (with old-key signature)

Step 5: Begin issuing new DATs with the NEW key
        └── DATs signed by either key remain verifiable as long as
            both verificationMethod entries are in the document.

Step 6: After transition window (recommended 7-14 days),
        remove the OLD key from the document
        ├── Build updated document with old key removed
        ├── Sign with the NEW key
        └── PUT /v1/aid/{did}

Step 7 (optional): Revoke any in-flight DATs signed by the old key
                   that you don't want to honour to expiry
        └── POST /v1/dat/revoke for each JTI
```

The continuity rule (step 3) is non-negotiable. An attacker with no key cannot insert their key into the document because they cannot sign the update.

### Cache implications

Verifiers SHOULD cache DID Documents with **TTL ≤ 5 minutes**. After step 5, expect up to 5 minutes of split state where some verifiers see only the old key. New DATs signed by the new key will fail verification against stale caches. Two ways to handle:

1. **Force-refresh hint** — verifiers MAY re-resolve immediately if a signature fails first-pass verification. Cost: one extra RTT on miss.
2. **Phased issuance** — wait 5 minutes after step 5 before issuing your first new-key DAT in production traffic.

---

## 4. SDK quick reference (Python)

```python
from idprova import AgentIdentity, KeyPair

# Step 1: existing identity
agent = AgentIdentity.from_did("did:aid:example.com:billing-agent")

# Step 2: generate new key
new_kp = KeyPair.generate()

# Step 3: build + submit document update (signs with old key automatically)
agent.add_key(new_kp)

# Step 4 (after transition window): retire old key
agent.remove_key(old_kp.kid)

# Step 5 (optional): emergency revoke any in-flight DATs from the old key
for jti in suspect_dat_jtis:
    agent.revoke_dat(jti, reason="emergency-rotation")
```

> **v0.1 status:** `add_key()` and `remove_key()` are stubbed for v0.1; the underlying DID Document update HTTP call is via `IDProvaClient.update_aid()`. Full SDK ergonomics ship in v0.2 (M4-M5 per Strategy v2). Until then, operators construct the updated document manually and submit via `update_aid()`.

---

## 5. Revocation vs rotation — what to use when

| Situation | Use | Why |
|---|---|---|
| Scheduled hygiene | Rotation | Non-disruptive; existing tokens honoured to expiry |
| Detected key compromise | **Both** — rotate first (issue new key), then revoke specific DATs you don't trust | Rotation stops new compromised tokens; revocation invalidates the historical ones still in flight |
| Specific DAT misuse | DAT revocation only | Don't rotate the issuer key for one bad token |
| Agent decommissioned | Remove key from document + revoke all of its DATs | The agent is gone; nothing it issued should be honoured |
| Legal hold / paused contract | DAT revocation per JTI | Surgical pause; rotation isn't the right tool |

### DAT revocation API

`POST /v1/dat/revoke`

```json
{
  "jti": "01HF1Z2T3K4N5V6Q7R8S9T0V1W",
  "revoked_by": "did:aid:example.com:soc-team",
  "reason": "key-compromise-investigation"
}
```

Verifiers MUST check `/v1/dat/revoked/{jti}` (or consume the issuer's revocation list at `.well-known/idprova/revocations.json`) before honouring a DAT. See protocol spec §5.6.

---

## 6. Air-gapped operations

In environments with no continuous registry connectivity:

### Rotation in air-gapped mode

- Generate the new key on the air-gapped side.
- Sign the updated DID Document offline with the old key.
- Carry the updated document to the registry over your established sync mechanism (signed bundle, sneakernet USB, periodic VPN window, etc.).
- The registry update is the synchronisation point — until it is delivered, verifiers on the other side of the air-gap will continue using the old key.

### Revocation in air-gapped mode

- Issuers maintain a local `revocations.json` and sign each entry.
- The signed revocation list is bundled with the registry sync delivery.
- Verifiers MUST consume the revocation list as part of their boot-time / sync-time procedure; they SHOULD NOT trust DATs signed during a sync gap until the gap is closed.

### Epoch model

For air-gapped systems, IDprova uses an **epoch counter**: each registry sync is an epoch. DATs MUST include the epoch they are valid in. Verifiers reject DATs from future epochs (impossible without time travel) and warn on DATs from epochs more than N behind current (configurable; default N=2).

> **v0.1 status:** epoch enforcement is implemented; revocation list distribution-as-a-service is on the v1.1 roadmap (see Cloud feature roadmap). Self-hosted operators run their own list distribution today.

---

## 7. Compromise recovery runbook

If a signing key is suspected or confirmed compromised:

```
T+0:00  DETECTION
        Signal: SOC alert / receipt anomaly / out-of-band report

T+0:05  CONTAIN
        - Stop the affected agent (if you can do so safely; do NOT crash production)
        - Preserve forensic state (memory dump, key store contents, recent logs)
        - Open incident ticket; page on-call

T+0:15  ROTATE
        - Generate new key
        - Submit updated DID Document signed by old key (this still works
          provided the attacker hasn't already submitted a malicious update —
          if they have, see §7.1 below)
        - Verify document on registry shows both keys

T+0:30  REVOKE
        - List all in-flight DATs signed by the compromised key
        - Bulk revoke each via /v1/dat/revoke with reason="key-compromise"
        - Push revocation list update for air-gapped consumers

T+1:00  COMMUNICATE
        - Notify downstream consumers (delegation chain children) of revocation
        - Customer-impact assessment if any tenant-facing DATs were revoked
        - SOC / compliance / legal teams briefed

T+24h   INVESTIGATE
        - Root cause analysis (how was the key obtained?)
        - Receipt log full audit for the compromise window
        - Determine if any actions taken under the compromised key
          must be reversed / refunded / re-authorised

T+1w    HARDEN
        - Implement controls to prevent recurrence
        - Update compromise simulation playbook
        - Schedule next compromise drill within 90 days
```

### 7.1 If the attacker has already submitted a malicious DID Document update

This is the worst case: the attacker rotated the key first, locking you out of your own identity.

Recovery requires registry intervention:
- The registry administrator can roll back the document to the previous version (state is versioned; see `idprova-registry` storage layer).
- The legitimate controller must re-establish identity through out-of-band proof (DNS TXT record refresh, organisational verification, etc.) — same flow as L1+ trust level establishment.
- All DATs signed under the attacker's key MUST be revoked at the registry level.
- Customers consuming the registry MUST refresh their cached documents.

This scenario is why `proof.proofValue` MUST always be verified against the **previous known-good key**, never against an arbitrary key claimed by the document being submitted.

---

## 8. Threat model integration

Cross-references to [STRIDE-THREAT-MODEL.md](STRIDE-THREAT-MODEL.md):

| Threat | Mitigation via rotation |
|---|---|
| KEY-S1 (private key theft) | Rotation limits exploitation window; revocation cuts in-flight tokens |
| KEY-T1 (key tampering in storage) | Rotation forces attacker to re-tamper; detection gap shrinks |
| KEY-I1 (memory leak / coredump) | Rotation invalidates the leaked material |
| KEY-E1 (unauthorised key issuance) | Continuity rule: new key must be signed by old key — prevents lateral key insertion |
| AID-T1 (registry compromise modifying AID) | Versioned rollback + out-of-band re-establishment |
| DAT-T2 (replay of expired/revoked DAT) | Revocation list + short DAT expiry + verifier MUST check |

---

## 9. What rotation does NOT solve

Rotation is one control, not the whole system. It does NOT solve:

- A compromised signing host where the attacker can intercept new keys as they're generated
- An adversary with persistent access to the controller's authentication credentials (they can rotate too — the legitimate operator and the attacker fight over who rotates last)
- Algorithm-level cryptographic breaks (those need migration to a different algorithm, see §4.5 of the protocol spec)
- Receipt forgery if the receipt-signing key is the compromised one (rotation prevents new forgeries; existing forged receipts in the chain are detectable via integrity check, but if they were countersigned by other valid parties the situation is more complex)
- Insider threats from a privileged operator with key access — those need separation of duties, not rotation

These need other controls (HSM-backed signing, separation of duties, multi-party signing for high-trust operations, ML-DSA-65 hybrid signing for post-quantum readiness, etc.) — see [security.md](security.md) for the full picture.

---

## 10. References

- Protocol Spec v0.1, §3.4.3 (DID Document Updates), §4.4.3 (Key Rotation), §4.4.4 (Key Revocation), §5.6 (DAT Revocation)
- STRIDE Threat Model, §2.2 (Key Management)
- security.md (cryptographic foundations)
- compliance.md (NIST SP 800-207 + ISM control mappings)
- controls.md (NIST 800-53 control mappings)
- W3C DID Core 1.0 §8 (Methods)
- NIST SP 800-57 Part 1 Rev 5 (Key Management Recommendations)
