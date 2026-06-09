#!/usr/bin/env python3
"""IDProva AutoGen quickstart — scope-gated tool execution demo.

Two tools, two scopes:
  - knowledge_base_search  -> mcp:tool:knowledge-base:read  (GRANTED)
  - send_email             -> mcp:tool:email:send           (NOT granted)

Run:
    python examples/autogen/quickstart.py

The guard allows the first tool and blocks the second, writing a verifiable
receipt for each. Verify the log with ``idprova receipt verify``.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from autogen_core import CancellationToken

from idprova_agents import ToolGuard
from idprova_agents.autogen_adapter import guarded_function_tool

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


async def main() -> None:
    signing_key = Ed25519PrivateKey.generate()
    receipts_path = Path(tempfile.mkdtemp()) / "receipts.jsonl"

    guard = ToolGuard(
        aid="did:aid:co:researcher",
        dat="dat-demo-autogen",
        signing_key=signing_key,
        scope_for_tool=lambda name: SCOPE_MAP.get(name, "mcp:tool:unknown:none"),
        granted_scopes=GRANTED_SCOPES,
        receipts_path=receipts_path,
    )

    kb_tool = guarded_function_tool(knowledge_base_search, guard)
    email_tool = guarded_function_tool(send_email, guard)
    ct = CancellationToken()

    print("=" * 60)
    print("IDProva AutoGen quickstart")
    print("=" * 60)

    print("\n[1] Calling knowledge_base_search (scope: mcp:tool:knowledge-base:read)")
    print("    Scope is GRANTED — tool will execute.")
    result = await kb_tool.run_json({"query": "quantum computing"}, ct)
    print(f"    Result: {kb_tool.return_value_as_string(result)}")

    print("\n[2] Calling send_email (scope: mcp:tool:email:send)")
    print("    Scope is NOT granted — guard will block.")
    try:
        await email_tool.run_json(
            {"to": "alice@example.com", "subject": "Hi", "body": "Hello"}, ct
        )
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
    asyncio.run(main())
