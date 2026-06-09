# IDProva — Launch Demo Recording Script

> The single highest-leverage GTM artifact (GTM plan, Dimension 2). A scripted,
> **reproducible, audience-verifiable** walkthrough — distinct from the E2E test.
> Primary asset for README + Show HN first comment + ASCA deck.
>
> **Recording doctrine (GTM plan §G / R1):** record this **off the R710**, on any
> laptop with the repo. The demo must not depend on the production host, so a dead
> demo box can never sink the pitch. Keep the recording as the launch artifact of
> record; a live on-stage run is optional gravy on top.

## What this proves (and the honesty boundary)

Three claims, in order of impact:

1. **Delegation is real, scoped, and time-boxed** — an operator grants a narrow,
   expiring authority to a specific agent (DAT).
2. **Verification needs no trust in us** — a third party verifies a token and a
   receipt chain **offline**, with only a public key.
3. **The record is anchored to a log nobody controls** — a receipt commitment sits
   on the public Sigstore Rekor transparency log; the viewer looks it up themselves.

**Honest framing — say this, don't overclaim** (GTM plan §B): the public-log entry
proves *"this commitment existed at time T and this agent's key signed it"* — **not**
"every action independently provable." Live auto-anchoring of every receipt is
**opt-in / roadmap**; what we show in Scene 4 is a **real entry our anchoring code
already produced** on the public log. That's an honest, strong claim and it works
today without the live submitter being wired (which is exactly why it's SPOF-free).

## Setup (once, before recording)

```bash
# From a fresh clone, off main:
cargo build -p idprova-cli           # debug build is fine; avoids the release LTO flake
cargo install --path crates/idprova-cli   # optional: puts `idprova` on PATH
# Dress rehearsal — run the harness end-to-end and watch it pass:
./docs/demo/run.sh
# or, without installing:  IDPROVA="cargo run -q -p idprova-cli --" ./docs/demo/run.sh
```

Recording tool: `asciinema rec idprova-demo.cast --idle-time-limit 2`.
Terminal: 100×30, large font, clean prompt (`PS1='$ '`). Type at a human pace.

---

## Scene 0 — Title (5s)

Type, don't rush:

```
# IDProva — verifiable, offline-checkable identity for AI agents (Apache-2.0)
# An operator delegates a narrow authority to one agent. A stranger verifies it
# without trusting us. The record is anchored to a public log nobody controls.
```

## Scene 1 — Identity + delegation (the core, ~40s)

Run the harness, or type the steps live. Commands are the repo's blessed quickstart.

```bash
# 1. The operator generates an Ed25519 keypair
idprova keygen --output operator.key
```
*Expected:* `Generated Ed25519 keypair:` + private/public paths + multibase pubkey.
`operator.key` (hex secret) and `operator.pub` (multibase public) are written.

```bash
# 2. Create the agent's identity document (AID)
idprova aid create \
  --id "did:aid:example.com:support-agent" \
  --name "Customer Support Agent" \
  --controller "did:aid:example.com:operator" \
  --key operator.key
```
*Expected:* pretty-printed AID JSON (W3C DID document with `did:aid:` method) +
`Saved to: did_aid_example.com_support-agent.json`.

```bash
# 3. Issue a scoped, time-boxed delegation token — read-only, one tool, 1h expiry
idprova dat issue \
  --issuer "did:aid:example.com:operator" \
  --subject "did:aid:example.com:support-agent" \
  --scope "mcp:tool:knowledge-base:read" \
  --expires-in 1h \
  --key operator.key
```
*Expected:* one line — the compact JWS token. **Copy it.**

## Scene 2 — The "no trust required" moment (~25s)

```bash
# 4. A third party verifies that token OFFLINE — only the PUBLIC key, no network
idprova dat verify <PASTE_TOKEN> \
  --key operator.pub \
  --scope "mcp:tool:knowledge-base:read"
```
*Expected (verbatim shape):*
```
IDProva DAT Verification
────────────────────────────────────────
Issuer:  did:aid:example.com:operator
Subject: did:aid:example.com:support-agent
JTI:     <uuid>
Scopes:  mcp:tool:knowledge-base:read
Expires: in ~3600s

✓ Signature:  VALID
✓ Timing:     VALID
✓ Scope:      'mcp:tool:knowledge-base:read' GRANTED
✓ Constraints: ALL PASS

Result: VALID
```
**Narration beat:** "No call to IDProva. No account. Just math and a public key."

## Scene 3 — Delegation chains + tamper-evident receipts (~30s)

From the repo root:

```bash
cargo run -q -p idprova-mcp --example multi_agent
```
*Expected:* a 4-agent chain — Operator → A (`mcp:tool:*:*`) → B
(`mcp:tool:filesystem:*`) → C (`mcp:tool:filesystem:read`). Agent C's
`filesystem:read` is **ALLOWED**; its `filesystem:write` and `search:execute` are
**BLOCKED** (scope can only narrow, never widen). Ends with the full receipt chain
and `Chain integrity: VALID`.

**Narration beat:** "Each hop can only narrow authority. Every action is a
hash-chained receipt — change one entry and the chain breaks."

## Scene 4 — The killer: verify on a public log nobody controls (~30s)

```bash
# A receipt commitment our anchoring code put on the PUBLIC Sigstore Rekor log.
# You don't have to trust us — look it up yourself:
curl -s "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=1687966334" | jq .
```
*Expected:* a real `hashedrekord` v0.0.1 entry, `data.hash.algorithm = sha512`,
with an inclusion proof and a signed entry timestamp (SET).

**Narration beat:** "That entry is on a public transparency log neither we nor the
agent operate. The commitment is opaque — the log learns nothing about the action —
but anyone can prove it existed at that time and was signed by this agent's key.
That's the difference between *'our dashboard says so'* and *independently provable.*"

Close on the one sentence:
```
# IDProva: open-protocol, offline-verifiable identity for AI agents —
# anchored to a public transparency log, sovereign-deployable, Apache-2.0.
```

---

## Post-production
- Trim dead air (`--idle-time-limit 2` already helps).
- Upload the `.cast`; embed in README, the Show HN first comment, and the deck.
- Pair it with [`VERIFY-YOURSELF.md`](./VERIFY-YOURSELF.md) — the static proof that
  survives skepticism after the video ends.

## Provenance of every command (so this script is auditable)
- Scenes 1–2: README "60-Second Quickstart" + the real `idprova-cli` surface
  (`crates/idprova-cli/src/main.rs`). Output shapes from `commands/{keygen,aid,dat}.rs`.
- Scene 3: `crates/idprova-mcp/examples/multi_agent.rs` (in-repo, runs today).
- Scene 4: logIndex **1687966334** and **1682925626** confirmed live on
  `rekor.sigstore.dev` (both `hashedrekord`/`sha512`, per ADR 0011). Rekor instance
  per `docs/adr/0011-rekor-transparency-anchor.md` + `crates/idprova-core/src/receipt/anchor.rs`.
