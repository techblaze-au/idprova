"""
demo_langchain_guarded.py
=========================

Proves the IDProva scope gate works with LangChain tools driven by a real LLM,
reusing the SAME identities/ folder as the CrewAI demo.

Run:  python demo_langchain_guarded.py
      (from a directory containing identities/researcher.{key,dat} and identities/writer.{key,dat})

Requires:
  - idprova_agents (ToolGuard, langchain_adapter.guarded_tool)
  - langchain_core, langchain_anthropic
  - an LLM (Option B style): IDPROVA_DEMO_MODEL_LC + ANTHROPIC_API_BASE + ANTHROPIC_API_KEY
"""

from __future__ import annotations

import os
import pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from idprova_agents import ToolGuard
from idprova_agents.langchain_adapter import guarded_tool
from langchain_core.tools import Tool

BASE = pathlib.Path(__file__).resolve().parent
IDENTITIES = BASE / "identities"
RECEIPTS = BASE / "receipts"
RECEIPTS.mkdir(exist_ok=True)

RESEARCHER_AID = "did:aid:techblaze.com.au:researcher"
WRITER_AID = "did:aid:techblaze.com.au:writer"


def load_identity(name: str):
    signing_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex((IDENTITIES / f"{name}.key").read_text().strip())
    )
    dat = (IDENTITIES / f"{name}.dat").read_text().strip()
    return signing_key, dat


def scope_for_tool(tool_name: str) -> str:
    return {
        "web_search": "mcp:tool:web-search:read",
        "knowledge_base": "mcp:tool:knowledge-base:read",
        "save_document": "mcp:tool:document:write",
    }[tool_name]


researcher_key, researcher_dat = load_identity("researcher")
writer_key, writer_dat = load_identity("writer")

researcher_guard = ToolGuard(
    aid=RESEARCHER_AID, dat=researcher_dat, signing_key=researcher_key,
    scope_for_tool=scope_for_tool,
    granted_scopes=["mcp:tool:web-search:read", "mcp:tool:knowledge-base:read"],
    receipts_path=RECEIPTS / "langchain_researcher.jsonl",
)
writer_guard = ToolGuard(
    aid=WRITER_AID, dat=writer_dat, signing_key=writer_key,
    scope_for_tool=scope_for_tool,
    granted_scopes=["mcp:tool:document:write"],
    receipts_path=RECEIPTS / "langchain_writer.jsonl",
)


def web_search(query: str) -> str:
    """Search the web for the given query."""
    return f"[web_search] Results for '{query}': verifiable agent identity uses DIDs + Ed25519 ..."


def knowledge_base(topic: str) -> str:
    """Look up a topic in the knowledge base."""
    return f"[knowledge_base] Entry for '{topic}': scoped DATs enable least-privilege delegation ..."


def save_document(content: str) -> str:
    """Save content to a document."""
    return f"[save_document] Document saved ({len(content)} chars)."


raw_web_search = Tool(name="web_search", description="Search the web", func=web_search, return_direct=False)
raw_knowledge_base = Tool(name="knowledge_base", description="Look up the knowledge base", func=knowledge_base, return_direct=False)
raw_save_document = Tool(name="save_document", description="Save a document", func=save_document, return_direct=False)

g_web_search = guarded_tool(raw_web_search, researcher_guard)
g_knowledge_base = guarded_tool(raw_knowledge_base, researcher_guard)
g_save_document_researcher = guarded_tool(raw_save_document, researcher_guard)
g_save_document_writer = guarded_tool(raw_save_document, writer_guard)

SEP = "=" * 72

print(SEP)
print("  LLM-DRIVEN EXERCISE (LangChain + real model)")
print(SEP)
try:
    from langchain_anthropic import ChatAnthropic

    model = os.environ.get("IDPROVA_DEMO_MODEL_LC", "claude-sonnet-4-6")
    llm = ChatAnthropic(
        model=model,
        base_url=os.environ.get("ANTHROPIC_API_BASE"),
        api_key=os.environ.get("ANTHROPIC_API_KEY"),
        max_tokens=1024,
    )
    researcher_tools = [g_web_search, g_knowledge_base, g_save_document_researcher]
    llm_with_tools = llm.bind_tools(researcher_tools)
    ai = llm_with_tools.invoke(
        "Research 'verifiable agent identity' using your tools, then try to save "
        "your findings with save_document."
    )
    by_name = {t.name: t for t in researcher_tools}
    calls = getattr(ai, "tool_calls", []) or []
    print(f"  model requested {len(calls)} tool call(s)")
    for tc in calls:
        t = by_name.get(tc["name"])
        if t is None:
            print(f"  [LLM->tool] {tc['name']} UNKNOWN (skipped)")
            continue
        try:
            out = t.invoke(tc["args"])
            print(f"  [LLM->tool] {tc['name']} ALLOWED -> {out[:60]}")
        except PermissionError as e:
            print(f"  [LLM->tool] {tc['name']} DENIED: {e}")
except Exception as exc:  # noqa: BLE001
    print(f"  LLM section skipped/failed: {type(exc).__name__}: {exc}")
    print("  Continuing to deterministic enforcement matrix ...")

print()
print(SEP)
print("  DETERMINISTIC ENFORCEMENT MATRIX (scope gate, no LLM involved)")
print(SEP)


def exercise(label, guard, tool, payload, expect_allowed):
    d = guard.check(tool, payload)
    guard.record(tool, payload, "success" if d.allowed else "denied")
    ok = d.allowed == expect_allowed
    print(f"  [{'OK' if ok else 'XX'}] {label:<36} -> {'ALLOWED' if d.allowed else 'DENIED'}")
    return ok


results = [
    exercise("researcher web_search   (read)", researcher_guard, "web_search",
             {"query": "verifiable agent identity"}, True),
    exercise("researcher save_document (write)", researcher_guard, "save_document",
             {"content": "findings"}, False),
    exercise("writer     save_document (write)", writer_guard, "save_document",
             {"content": "final report"}, True),
]
print(f"\n  Enforcement matrix: {'ALL CORRECT' if all(results) else 'SOME FAILURES'}")

r1 = RECEIPTS / "langchain_researcher.jsonl"
r2 = RECEIPTS / "langchain_writer.jsonl"
print("\n" + SEP)
print("  RECEIPT FILES (verify offline, public key only)")
print(SEP)
print(f"  Researcher : {r1}")
print(f"  Writer     : {r2}")
print(f"\n  idprova receipt verify {r1}")
print(f"  idprova receipt verify {r2}")
