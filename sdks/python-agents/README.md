# idprova-agents

Verifiable, scope-gated tool execution for AI agent frameworks.

`idprova-agents` wraps your agent's tool calls with a **scope gate** (the agent
may only call tools its delegation token permits) and writes a **signed,
hash-chained receipt** for every call — allowed or denied. Receipts verify
independently with the `idprova` CLI (`idprova receipt verify receipts.jsonl`),
so the audit trail does not depend on trusting the agent or this library.

Part of the [IDProva](https://github.com/techblaze-au/idprova) project.

## Install

Not yet on PyPI. Install from the repository:

```bash
pip install "idprova-agents[langchain] @ git+https://github.com/techblaze-au/idprova#subdirectory=sdks/python-agents"
```

Or, from a clone:

```bash
pip install "./sdks/python-agents[langchain]"
```

## Quickstart

See [`examples/langchain/quickstart.py`](../../examples/langchain/quickstart.py)
for a runnable end-to-end demo (allow an in-scope tool, block an out-of-scope
tool, emit verifiable receipts).

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from langchain_core.tools import Tool
from idprova_agents import ToolGuard, guarded_tool

SCOPES = {"knowledge_base_search": "mcp:tool:knowledge-base:read"}
guard = ToolGuard(
    aid="did:aid:co:support-agent",
    dat="dat-...",
    signing_key=Ed25519PrivateKey.generate(),
    scope_for_tool=lambda name: SCOPES.get(name, "mcp:tool:unknown:none"),
    granted_scopes=["mcp:tool:knowledge-base:read"],
    receipts_path="receipts.jsonl",
)
kb = guarded_tool(Tool.from_function(
    func=your_kb_search, name="knowledge_base_search", description="Search the KB"), guard)
kb.invoke("quantum computing")   # runs + writes a "success" receipt
```

## What's included

- `ToolGuard` — scope check + signed receipt emission.
- `guarded_tool()` — wrap a LangChain `Tool` so its execution is scope-gated.
- `IDProvaGuardCallbackHandler` — LangChain callback handler (enforce or audit-only).

Adapters for additional frameworks (CrewAI, AutoGen) are planned as optional
extras.

## Licence

Apache-2.0.
