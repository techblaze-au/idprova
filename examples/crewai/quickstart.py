#!/usr/bin/env python3
"""IDProva CrewAI quickstart — scope-gated tool execution demo.

Two tools, two scopes:
  - knowledge_base_search  -> mcp:tool:knowledge-base:read  (GRANTED)
  - send_email             -> mcp:tool:email:send           (NOT granted)

Run:
    python examples/crewai/quickstart.py

The guard allows the first tool and blocks the second, writing a verifiable
receipt for each. Verify the log with ``idprova receipt verify``.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from idprova_agents import ToolGuard
from idprova_agents.crewai_adapter import guarded_crewai_tool

SCOPE_MAP = {
    "knowledge_base_search": "mcp:tool:knowledge-base:read",
    "send_email": "mcp:tool:email:send",
}
GRANTED_SCOPES = ["mcp:tool:knowledge-base:read"]


def knowledge_base_search(query: str) -> str:
    """Search the internal knowledge base."""
    return f"Results for '{query}': [quantum computing overview, qubit fundamentals]"


def send_email(to: str, subject: str, body: str) -> str:
    """Send an email via the corporate mail server."""
    return f"Email sent to {to}: {subject}"


def main() -> None:
    signing_key = Ed25519PrivateKey.generate()
    receipts_path = Path(tempfile.mkdtemp()) / "receipts.jsonl"

    guard = ToolGuard(
        aid="did:aid:co:researcher",
        dat="dat-demo-crewai",
        signing_key=signing_key,
        scope_for_tool=lambda name: SCOPE_MAP.get(name, "mcp:tool:unknown:none"),
        granted_scopes=GRANTED_SCOPES,
        receipts_path=receipts_path,
    )

    kb_tool = guarded_crewai_tool(knowledge_base_search, guard)
    email_tool = guarded_crewai_tool(send_email, guard)

    print("=" * 60)
    print("IDProva CrewAI quickstart")
    print("=" * 60)

    print("\n[1] Calling knowledge_base_search (scope: mcp:tool:knowledge-base:read)")
    print("    Scope is GRANTED — tool will execute.")
    result = kb_tool.run(query="quantum computing")
    print(f"    Result: {result}")

    print("\n[2] Calling send_email (scope: mcp:tool:email:send)")
    print("    Scope is NOT granted — guard will block.")
    try:
        email_tool.run(to="alice@example.com", subject="Hi", body="Hello")
        print("    Result: executed (unexpected)")
    except PermissionError as exc:
        print(f"    BLOCKED: {exc}")

    print("\n" + "=" * 60)
    print("Receipts written to:")
    print(f"  {receipts_path}")
    print()
    print("Verify with:")
    print(f"  idprova receipt verify {receipts_path}")
    print("=" * 60)

    print("\nReceipt log:")
    for i, line in enumerate(receipts_path.read_text().strip().splitlines()):
        print(f"  [{i}] {line}")


if __name__ == "__main__":
    main()
