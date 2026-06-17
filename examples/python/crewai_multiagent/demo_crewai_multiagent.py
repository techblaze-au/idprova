"""
IDProva CrewAI Multi-Agent Demo
================================
Proves the IDProva agent-identity guard works inside a CrewAI multi-agent
pipeline.  Two agents (Researcher & Writer) are driven by a real OpenAI LLM
(gpt-4o-mini).  The Researcher is granted only *read* scopes, so when it
attempts to call `save_document` the guard **denies** the call (raises
PermissionError) and records a "denied" receipt.  The Writer, which holds the
`document:write` scope, succeeds.

Run:
    python demo_crewai_multiagent.py

Prerequisites:
    - OPENAI_API_KEY env var set
    - identities/ folder with researcher.{key,dat} and writer.{key,dat}
    - pip install crewai idprova-agents cryptography blake3
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from idprova_agents import ToolGuard
from idprova_agents.crewai_adapter import guarded_crewai_tool

from crewai import Agent, Task, Crew, Process, LLM


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def load_key(path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a 64-hex-char seed file."""
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(Path(path).read_text().strip())
    )


def read_dat(path) -> str:
    """Read and strip a DAT token file."""
    return Path(path).read_text().strip()


# --------------------------------------------------------------------------
# Paths (relative to this script)
# --------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
IDENTITIES = BASE_DIR / "identities"
RECEIPTS_DIR = BASE_DIR / "receipts"
RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------
# Agent identities
# --------------------------------------------------------------------------

RESEARCHER_AID = "did:aid:techblaze.com.au:researcher"
WRITER_AID = "did:aid:techblaze.com.au:writer"

_SCOPE_MAP = {
    "web_search":     "mcp:tool:web-search:read",
    "knowledge_base": "mcp:tool:knowledge-base:read",
    "save_document":  "mcp:tool:document:write",
}


def scope_for_tool(tool_name: str) -> str:
    """Return the 4-part scope required for *tool_name*."""
    return _SCOPE_MAP.get(tool_name, f"mcp:tool:{tool_name}:read")


# Granted scopes — hard-coded to match each agent's DAT.
RESEARCHER_SCOPES = ["mcp:tool:web-search:read", "mcp:tool:knowledge-base:read"]
WRITER_SCOPES = ["mcp:tool:document:write"]

# --------------------------------------------------------------------------
# ToolGuards
# --------------------------------------------------------------------------

researcher_guard = ToolGuard(
    aid=RESEARCHER_AID,
    dat=read_dat(IDENTITIES / "researcher.dat"),
    signing_key=load_key(IDENTITIES / "researcher.key"),
    scope_for_tool=scope_for_tool,
    granted_scopes=RESEARCHER_SCOPES,
    receipts_path=RECEIPTS_DIR / "researcher.jsonl",
)

writer_guard = ToolGuard(
    aid=WRITER_AID,
    dat=read_dat(IDENTITIES / "writer.dat"),
    signing_key=load_key(IDENTITIES / "writer.key"),
    scope_for_tool=scope_for_tool,
    granted_scopes=WRITER_SCOPES,
    receipts_path=RECEIPTS_DIR / "writer.jsonl",
)

# --------------------------------------------------------------------------
# Plain tool functions
# --------------------------------------------------------------------------


def web_search(query: str) -> str:
    """Search the web for information on the given query."""
    return (
        f"Web search results for '{query}': Verifiable identity for AI agents "
        "leverages decentralized identifiers (DIDs) and Ed25519 keys so every "
        "tool invocation carries a provable, scoped identity token — enabling "
        "least-privilege delegation and tamper-evident audit trails."
    )


def knowledge_base(topic: str) -> str:
    """Look up information in the internal knowledge base."""
    return (
        f"Knowledge-base entry for '{topic}': An agent-identity guard intercepts "
        "each tool call, checks the caller's granted scopes against the required "
        "scope, and permits or denies execution. Every decision is recorded as a "
        "signed receipt for offline verification."
    )


def save_document(content: str) -> str:
    """Save content to disk and return a confirmation message."""
    out = BASE_DIR / "output_document.md"
    out.write_text(content, encoding="utf-8")
    return f"Document saved successfully to {out}"


# --------------------------------------------------------------------------
# Guard-wrapped tools
# --------------------------------------------------------------------------

# Researcher: save_document is intentionally wrapped with the *researcher*
# guard, which lacks mcp:tool:document:write -> the call will be DENIED.
researcher_web_search = guarded_crewai_tool(
    web_search, researcher_guard,
    name="web_search", description="Search the web for information on a query",
)
researcher_knowledge_base = guarded_crewai_tool(
    knowledge_base, researcher_guard,
    name="knowledge_base", description="Look up information in the knowledge base",
)
researcher_save_document = guarded_crewai_tool(
    save_document, researcher_guard,
    name="save_document", description="Save a document to disk",
)

# Writer: save_document wrapped with writer_guard (has document:write) -> ALLOWED.
writer_save_document = guarded_crewai_tool(
    save_document, writer_guard,
    name="save_document", description="Save a document to disk",
)

# --------------------------------------------------------------------------
# Agents
# --------------------------------------------------------------------------

# LLM is env-configurable so this example is portable:
#   - default: OpenAI gpt-4o-mini (needs OPENAI_API_KEY)
#   - any anthropic/* model id + ANTHROPIC_API_BASE/KEY routes via that gateway
_model = os.environ.get("IDPROVA_DEMO_MODEL", "gpt-4o-mini")
if _model.startswith("anthropic/") or os.environ.get("ANTHROPIC_API_BASE"):
    LLM = LLM(
        model=_model,
        base_url=os.environ.get("ANTHROPIC_API_BASE"),
        api_key=os.environ.get("ANTHROPIC_API_KEY"),
    )
else:
    LLM = _model

researcher = Agent(
    role="Researcher",
    goal=(
        "Research the topic 'verifiable identity for AI agents' using web search "
        "and the knowledge base. After gathering findings, ATTEMPT to save them "
        "using save_document."
    ),
    backstory="A diligent researcher who always tries to persist findings to disk.",
    tools=[researcher_web_search, researcher_knowledge_base, researcher_save_document],
    llm=LLM,
    verbose=True,
)

writer = Agent(
    role="Writer",
    goal="Write a polished final document on the topic and save it.",
    backstory="A skilled technical writer who produces clear documents and saves them.",
    tools=[writer_save_document],
    llm=LLM,
    verbose=True,
)

# --------------------------------------------------------------------------
# Tasks (sequential: research -> write)
# --------------------------------------------------------------------------

research_task = Task(
    description=(
        "Research 'verifiable identity for AI agents' using web_search and "
        "knowledge_base. Then ATTEMPT to save your findings with save_document."
    ),
    expected_output="A research summary, plus an attempted (possibly denied) save.",
    agent=researcher,
)

write_task = Task(
    description=(
        "Using the prior research, write a polished final document on "
        "'verifiable identity for AI agents' and save it with save_document."
    ),
    expected_output="A polished document, confirmed saved to disk.",
    agent=writer,
    context=[research_task],
)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    process=Process.sequential,
    verbose=True,
)

# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------

SEP = "=" * 72

print(SEP)
print("  IDProva CrewAI Multi-Agent Demo")
print(SEP)
print("  Topic            : verifiable identity for AI agents")
print(f"  Researcher AID   : {RESEARCHER_AID}")
print(f"  Writer AID       : {WRITER_AID}")
print(f"  Researcher scopes: {RESEARCHER_SCOPES}")
print(f"  Writer scopes    : {WRITER_SCOPES}")
print("  Expected behaviour:")
print("    - web_search / knowledge_base by Researcher -> ALLOWED")
print("    - save_document by Researcher               -> DENIED (no document:write)")
print("    - save_document by Writer                   -> ALLOWED")
print(SEP)

try:
    result = crew.kickoff()
    print("\n" + SEP)
    print("  CREW RESULT")
    print(SEP)
    print(result)
except Exception as exc:  # noqa: BLE001
    print(f"\n[!] Crew execution error: {type(exc).__name__}: {exc}")
    print("    (May be an OpenAI limit/network error. Receipts below still stand.)")

# --------------------------------------------------------------------------
# Deterministic enforcement matrix (independent of LLM tool-choice)
# --------------------------------------------------------------------------
# A real agent's *choice* to call a tool is LLM-driven and varies run to run,
# so the crew above may or may not exercise every path. The block below drives
# the SAME scope gate the adapter applies on every call (check -> record) for
# all three cases, so the proof is reliable regardless of the LLM. These
# receipts append to each agent's existing hash chain.
print("\n" + SEP)
print("  DETERMINISTIC ENFORCEMENT MATRIX (scope gate, no LLM involved)")
print(SEP)


def _exercise(label, guard, tool, payload, expect_allowed):
    d = guard.check(tool, payload)
    guard.record(tool, payload, "success" if d.allowed else "denied")
    ok = (d.allowed == expect_allowed)
    verdict = "ALLOWED" if d.allowed else "DENIED"
    mark = "OK" if ok else "XX"
    print(f"  [{mark}] {label:<40} -> {verdict}")
    if not ok:
        print(f"        UNEXPECTED — gate said: {d.reason}")
    return ok


_all_ok = True
_all_ok &= _exercise("Researcher web_search   (read)", researcher_guard,
                     "web_search", {"query": "agent identity"}, True)
_all_ok &= _exercise("Researcher save_document (write)", researcher_guard,
                     "save_document", {"content": "..."}, False)
_all_ok &= _exercise("Writer     save_document (write)", writer_guard,
                     "save_document", {"content": "final doc"}, True)
print(f"\n  Enforcement matrix: {'ALL CORRECT' if _all_ok else 'MISMATCH — see above'}")

r1 = RECEIPTS_DIR / "researcher.jsonl"
r2 = RECEIPTS_DIR / "writer.jsonl"
print("\n" + SEP)
print("  RECEIPT FILES (verify offline, public key only)")
print(SEP)
print(f"  Researcher : {r1}")
print(f"  Writer     : {r2}")
print("\n  Verify with:")
print(f"    idprova receipt verify {r1}")
print(f"    idprova receipt verify {r2}")
print(SEP)
