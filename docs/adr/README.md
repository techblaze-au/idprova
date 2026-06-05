# Architecture Decision Records (ADRs)

This directory captures architecturally significant decisions for the IDProva
protocol and reference implementation. Each ADR records the context, the
options considered, the decision taken, and the consequences. ADRs are
append-only; an existing ADR is never edited in place once accepted — it is
superseded by a new ADR that links back to it.

## Format

We follow Michael Nygard's lightweight ADR template:

```
# {NNNN} — {Title}

* **Status:** Proposed | Accepted | Deprecated | Superseded by {ADR-NNNN}
* **Date:** {YYYY-MM-DD}
* **Authors:** {names}
* **Related:** {issue / PR / RFC links}

## Context
{What problem are we trying to solve? What forces are in play?}

## Decision
{The decision, stated clearly and unambiguously.}

## Consequences
{What changes as a result? Positive, negative, and neutral consequences.}

## Alternatives considered
{Other options we evaluated and why we rejected them.}

## References
{Pointers to RFCs, prior ADRs, external standards, related issues.}
```

## Numbering

ADRs are numbered with a four-digit zero-padded prefix matching the order they
were proposed (not the order they were accepted). The current sequence:

| ID   | Title                                  | Status   |
|------|----------------------------------------|----------|
| 0003 | Tenant boundary in registry, not core  | Proposed |
| 0011 | Transparency anchoring via Sigstore Rekor | Accepted |
| 0012 | Privacy-preserving batched anchoring   | Proposed |

ADRs 0001 and 0002 are reserved for retrospective records of decisions that
shipped before this ADR process was introduced (specifically: the choice of
Rust as the core implementation language, and the choice of BLAKE3 as the
canonical hash primitive). They may be backfilled later.

ADR 0004 (`pq-hybrid-signing`) is planned per backlog entry IDP-006.

## Lifecycle

- A new ADR starts in **Proposed** status. It is opened as a PR for review.
- After review, the PR is merged with the ADR in **Accepted** status.
- If a later ADR overturns an earlier decision, the earlier ADR is moved to
  **Superseded by {ADR-NNNN}** in a follow-up PR that updates only the
  status / date / pointer — the body is preserved unchanged.
- **Deprecated** is used when an ADR's context no longer applies but no
  successor decision is required (e.g., a feature is removed entirely).
