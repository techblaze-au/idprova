"""
demo_autogen_guarded.py
=======================

Proves the IDProva scope gate works with AutoGen (autogen-agentchat 0.7.x)
tools driven by a real LLM, reusing the SAME identities/ folder.

Run:  python demo_autogen_guarded.py
Requires identities/researcher.{key,dat} and identities/writer.{key,dat}, plus
an LLM (IDPROVA_DEMO_MODEL_AG + ANTHROPIC_API_BASE + ANTHROPIC_API_KEY). Python 3.12+
"""

from __future__ import annotations

import asyncio
import os
import pathlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from idprova_agents import ToolGuard
from idprova_agents.autogen_adapter import guarded_function_tool

_HERE = pathlib.Path(__file__).resolve().parent
_IDS = _HERE / "identities"
_RECEIPTS = _HERE / "receipts"
_RECEIPTS.mkdir(exist_ok=True)


def _load_key(path: pathlib.Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text().strip()))


def _load_dat(path: pathlib.Path) -> str:
    return path.read_text().strip()


researcher_key = _load_key(_IDS / "researcher.key")
researcher_dat = _load_dat(_IDS / "researcher.dat")
writer_key = _load_key(_IDS / "writer.key")
writer_dat = _load_dat(_IDS / "writer.dat")

RESEARCHER_AID = "did:aid:techblaze.com.au:researcher"
WRITER_AID = "did:aid:techblaze.com.au:writer"


def _scope_for_tool(tool_name: str) -> str:
    return {
        "web_search": "mcp:tool:web-search:read",
        "knowledge_base": "mcp:tool:knowledge-base:read",
        "save_document": "mcp:tool:document:write",
    }[tool_name]


researcher_guard = ToolGuard(
    aid=RESEARCHER_AID, dat=researcher_dat, signing_key=researcher_key,
    scope_for_tool=_scope_for_tool,
    granted_scopes=["mcp:tool:web-search:read", "mcp:tool:knowledge-base:read"],
    receipts_path=str(_RECEIPTS / "autogen_researcher.jsonl"),
)
writer_guard = ToolGuard(
    aid=WRITER_AID, dat=writer_dat, signing_key=writer_key,
    scope_for_tool=_scope_for_tool,
    granted_scopes=["mcp:tool:document:write"],
    receipts_path=str(_RECEIPTS / "autogen_writer.jsonl"),
)


def web_search(query: str) -> str:
    """Search the web for the given query and return relevant results."""
    return f"[web_search '{query}']: verifiable agent identity scopes tool access via DATs."


def knowledge_base(topic: str) -> str:
    """Retrieve information from the internal knowledge base on a given topic."""
    return f"[knowledge_base '{topic}']: scoped DATs give cryptographic proof of grants."


def save_document(content: str) -> str:
    """Save the given content as a document to persistent storage."""
    return f"[save_document] Saved {len(content)} characters."


g_web_search = guarded_function_tool(web_search, researcher_guard, name="web_search",
                                     description="Search the web for a query.")
g_knowledge_base = guarded_function_tool(knowledge_base, researcher_guard, name="knowledge_base",
                                         description="Look up a topic in the knowledge base.")
g_save_document_researcher = guarded_function_tool(save_document, researcher_guard, name="save_document",
                                                   description="Save content as a document.")
g_save_document_writer = guarded_function_tool(save_document, writer_guard, name="save_document",
                                               description="Save content as a document.")

print("=" * 70)
print("PART 1: AutoGen LLM demo with IDProva guarded tools")
print("=" * 70)
try:
    from autogen_agentchat.agents import AssistantAgent
    from autogen_ext.models.anthropic import AnthropicChatCompletionClient

    client = AnthropicChatCompletionClient(
        model=os.environ.get("IDPROVA_DEMO_MODEL_AG", "claude-sonnet-4-6"),
        api_key=os.environ.get("ANTHROPIC_API_KEY"),
        base_url=os.environ.get("ANTHROPIC_API_BASE"),
        model_info={"vision": False, "function_calling": True, "json_output": False,
                    "family": "unknown", "structured_output": False},
    )

    async def main() -> None:
        agent = AssistantAgent(
            name="researcher", model_client=client,
            tools=[g_web_search, g_knowledge_base, g_save_document_researcher],
            reflect_on_tool_use=False,
        )
        try:
            result = await agent.run(
                task="Research 'verifiable agent identity' using web_search and "
                     "knowledge_base, then try to save with save_document."
            )
            for m in result.messages:
                print("  [msg]", getattr(m, "source", "?"), "::",
                      str(getattr(m, "content", ""))[:80])
        except Exception as e:  # noqa: BLE001
            print("  AutoGen run skipped/failed:", type(e).__name__, str(e)[:100])
        finally:
            await client.close()

    asyncio.run(main())
except Exception as exc:  # noqa: BLE001
    print("  AutoGen LLM block skipped:", type(exc).__name__, str(exc)[:120])

print()
print("=" * 70)
print("PART 2: Deterministic enforcement matrix (no LLM)")
print("=" * 70)


def exercise(label, guard, tool, payload, expect_allowed):
    d = guard.check(tool, payload)
    guard.record(tool, payload, "success" if d.allowed else "denied")
    ok = d.allowed == expect_allowed
    print(f"  [{'OK' if ok else 'XX'}] {label:<46} -> {'ALLOWED' if d.allowed else 'DENIED'}")
    return ok


results = [
    exercise("researcher web_search    (read)", researcher_guard, "web_search",
             {"query": "verifiable agent identity"}, True),
    exercise("researcher save_document (write, not granted)", researcher_guard, "save_document",
             {"content": "text"}, False),
    exercise("writer     save_document (write)", writer_guard, "save_document",
             {"content": "text"}, True),
]
print(f"\nEnforcement matrix: {'ALL CORRECT' if all(results) else 'FAILURES DETECTED'}")

r1 = _RECEIPTS / "autogen_researcher.jsonl"
r2 = _RECEIPTS / "autogen_writer.jsonl"
print("\n" + "=" * 70)
print("Receipt files (verify offline):")
print(f"  {r1}\n  {r2}")
print(f"\n  idprova receipt verify {r1}")
print(f"  idprova receipt verify {r2}")
