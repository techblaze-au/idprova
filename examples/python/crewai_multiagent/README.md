# CrewAI Multi-Agent Demo — verifiable agent identity, capability & accountability

Two [CrewAI](https://github.com/crewAIInc/crewAI) agents run in one crew, each operating under its own
IDProva identity:

- a **Researcher** holding a read-only DAT (`web-search:read`, `knowledge-base:read`), and
- a **Writer** holding a write DAT (`document:write`).

Every tool call passes through an IDProva `ToolGuard` that checks the agent's granted scopes
*before* the tool runs. The Researcher's `web_search` / `knowledge_base` calls are **allowed**;
its attempt to `save_document` is **denied** (it has no `document:write` scope). The Writer's
`save_document` is **allowed**. Every decision — allow *and* deny — is written as a signed,
BLAKE3 hash-chained receipt that verifies **offline, with only the public key**.

This is the full IDProva flywheel — **Identity → Capability → Accountability** — proven inside a
real, LLM-driven multi-agent framework.

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.12** | `python --version` |
| **`idprova` CLI** on PATH | `cargo install idprova` or download a release binary |
| **An LLM** | see options below |

### LLM options

**Option A — OpenAI (default, model `gpt-4o-mini`)**

```bash
export OPENAI_API_KEY="sk-..."
```

**Option B — any other model via LiteLLM**

```bash
export IDPROVA_DEMO_MODEL="anthropic/claude-sonnet-4-6"
export ANTHROPIC_API_BASE="https://api.anthropic.com"
export ANTHROPIC_API_KEY="sk-ant-..."
pip install litellm        # required for non-native providers
```

## Setup

```bash
pip install -r requirements.txt
bash setup_identities.sh          # creates keys, AIDs and DATs under identities/
```

## Run

```bash
python demo_crewai_multiagent.py
```

The script runs the live CrewAI crew (whose tool calls are LLM-driven and vary run to run),
then prints a **deterministic enforcement matrix** that drives the same scope gate for every
case so the result is reliable regardless of the model — it even runs if no LLM is configured:

```
  DETERMINISTIC ENFORCEMENT MATRIX (scope gate, no LLM involved)
  [OK] Researcher web_search   (read)      -> ALLOWED
  [OK] Researcher save_document (write)    -> DENIED
  [OK] Writer     save_document (write)    -> ALLOWED
  Enforcement matrix: ALL CORRECT
```

Receipts are written to `receipts/researcher.jsonl` and `receipts/writer.jsonl`.

## Verify offline

```bash
idprova receipt verify receipts/researcher.jsonl
idprova receipt verify receipts/writer.jsonl
```

Both print `Receipt chain integrity: VALID`. No network is contacted — verification uses only the
public key, so anyone holding a receipt log can independently confirm what each agent did.

## What this demonstrates

| Pillar | Concrete artifact |
|---|---|
| **Identity** | AID documents (`identities/*.aid.json`) — DID-style identifiers bound to Ed25519 keys |
| **Capability** | DATs (`identities/*.dat`) — issuer-signed, scope-limited delegation tokens |
| **Accountability** | hash-chained receipt logs (`receipts/*.jsonl`) — every allowed *and denied* action, verifiable offline |

## Same proof in other frameworks

This folder also ships the identical Identity → Capability → Accountability proof in two more
popular frameworks, reusing the same `identities/` (run `setup_identities.sh` once):

| File | Framework | Run |
|---|---|---|
| `demo_crewai_multiagent.py` | CrewAI | `python demo_crewai_multiagent.py` |
| `demo_langchain_guarded.py` | LangChain (`langchain-core` + `langchain-anthropic`) | `pip install langchain-anthropic` then `python demo_langchain_guarded.py` |
| `demo_autogen_guarded.py` | AutoGen (`autogen-agentchat` 0.7.x) | `pip install "autogen-agentchat" "autogen-ext[anthropic]"` then `python demo_autogen_guarded.py` |

The LangChain and AutoGen variants drive a model via `langchain-anthropic` / AutoGen's Anthropic
client — set `IDPROVA_DEMO_MODEL_LC` / `IDPROVA_DEMO_MODEL_AG` plus `ANTHROPIC_API_BASE` and
`ANTHROPIC_API_KEY`. Each prints the same deterministic enforcement matrix and writes
offline-verifiable receipts (`receipts/langchain_*.jsonl`, `receipts/autogen_*.jsonl`).

## Note

`identities/`, `receipts/` and `output_document.md` are generated locally and **gitignored**
(see the `.gitignore` in this folder). Never commit private keys.
