# Verify it yourself

You don't have to trust IDProva, and you don't have to trust the agent that
produced this record. A commitment to an IDProva Action Receipt is recorded on the
**public [Sigstore Rekor](https://rekor.sigstore.dev) transparency log** — an
append-only, Merkle-tree log operated by the Sigstore project, **not by us**.

Here is a real entry. Look it up:

## 1. Pull the entry from the public log

```bash
curl -s "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=1687966334" | jq .
```

You will get back a real `hashedrekord` entry:

| Field | Value |
|---|---|
| **Rekor instance** | `https://rekor.sigstore.dev` (public, Sigstore-operated) |
| **logIndex** | `1687966334` |
| **Entry UUID** | `108e9186e8c5677adff6852c97a3d144231d9df986efd4c8c37caeb67c05514297fb62a892b9b20f` |
| **Entry kind** | `hashedrekord` v0.0.1 |
| **Hash algorithm** | `sha512` |
| **Anchored hash** | `428a8d80e212e3a9f9478cef7e12cc0db27d31587a95cf378e56b2d282ee392c90dc248a1ee0ac5c083595ea1ecec70acbe0e18848d0a43eedaec62b45f3dffa` |

(A second confirming entry: `logIndex=1682925626`.)

The response includes an **inclusion proof** and a **signed entry timestamp (SET)**
— the cryptographic evidence that this commitment was in the log at a specific time,
witnessed by a log neither we nor the agent control.

## 2. Confirm it with the official Rekor client (optional)

```bash
# install: https://docs.sigstore.dev/rekor/installation
rekor-cli get --log-index 1687966334 --rekor_server https://rekor.sigstore.dev
```

`rekor-cli` independently fetches the entry and **verifies the inclusion proof and
the SET against Rekor's own public key** — no IDProva code in the loop at all.

## 3. What this does — and does not — prove

**Proves:** this exact commitment (a SHA-512 over the receipt's signed payload)
existed on a public append-only log at the recorded time, signed with the agent's
Ed25519 key (Ed25519ph). A third party — a regulator, a counterparty, an insurer —
can confirm that **without trusting IDProva or the agent host**, and even **offline**
given a cached Rekor public key + checkpoint.

**Does not prove:** that the underlying action was *authorized* or that it *happened*
in the world — a transparency log records *existence and time*, not *truth of the
event*. The agent **signature** is what binds "this agent asserted this"; the anchor
adds trusted time + non-repudiation-of-existence on top.

The honest one-line claim:

> A verifiable, independently-timestamped commitment that **this agent** asserted
> **this action** at **this time** — checkable without trusting us.

## 4. Privacy

Only an **opaque commitment** leaves the trust boundary — never the action, the DID,
or any payload content. Rekor learns nothing about what the agent did. (In v0.3 the
production design batches commitments under a per-tenant salted HMAC + a periodic
Merkle root; see [ADR 0012](../adr/0012-privacy-preserving-batched-anchoring.md).
Anchoring is **opt-in / default-off** — see [ADR 0011](../adr/0011-rekor-transparency-anchor.md).)

## 5. Make your own

```bash
# Build, then run the golden-path demo end to end:
cargo build -p idprova-cli
./docs/demo/run.sh
```

Watch the [demo recording](./SCRIPT.md) for the full 2-minute walkthrough.

---
*Roadmap-honest note: today's anchor targets the public `rekor.sigstore.dev`. A
self-hostable transparency log (for sovereign / air-gapped deployments) is on the
roadmap behind the swappable `TransparencyLog` trait — the verification model above
is unchanged when the log is yours.*
