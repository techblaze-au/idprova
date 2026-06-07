#!/usr/bin/env python3
"""IDProva LangChain quickstart — scope-gated tool execution demo.

Two tools, two scopes:
  - knowledge_base_search  → mcp:tool:knowledge-base:read  (GRANTED)
  - send_email             → mcp:tool:email:send           (NOT granted)

Run:
    python examples/langchain/quickstart.py

Output shows the guard allowing the first tool and blocking the second,
then prints the receipts.jsonl path for verification with
``idprova receipt verify``.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from idprova_agents.guard import ToolGuard
from idprova_agents.langchain_adapter import IDProvaGuardCallbackHandler, guarded_tool

# ── Tool definitions ─────────────────────────────────────────────────────

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


# ── Build guard + tools ──────────────────────────────────────────────────

def main() -> None:
    # Generate an ephemeral Ed25519 key for this demo
    signing_key = Ed25519PrivateKey.generate()

    # Temp directory for receipts so the demo is self-contained
    receipts_path = Path(tempfile.mkdtemp()) / "receipts.jsonl"

    guard = ToolGuard(
        aid="did:aid:co:researcher",
        dat="dat-demo-quickstart",
        signing_key=signing_key,
        scope_for_tool=lambda tool_name: SCOPE_MAP.get(tool_name, "mcp:tool:unknown:none"),
        granted_scopes=GRANTED_SCOPES,
        receipts_path=receipts_path,
    )

    handler = IDProvaGuardCallbackHandler(guard)

    # ── Run both tools ───────────────────────────────────────────────────

    print("=" * 60)
    print("IDProva LangChain quickstart")
    print("=" * 60)

    # Tool 1: in-scope — should succeed
    print("\n[1] Calling knowledge_base_search (scope: mcp:tool:knowledge-base:read)")
    print("    Scope is GRANTED — tool will execute.")

    # Simulate on_tool_start / on_tool_end callback flow
    serialized = {"name": "knowledge_base_search"}
    input_str = "quantum computing"
    handler.on_tool_start(serialized, input_str)
    result1 = knowledge_base_search(input_str)
    handler.on_tool_end(result1)
    print(f"    Result: {result1}")

    # Tool 2: out-of-scope — should be blocked
    print("\n[2] Calling send_email (scope: mcp:tool:email:send)")
    print("    Scope is NOT granted — guard will block.")

    serialized2 = {"name": "send_email"}
    input_str2 = '{"to": "alice@example.com", "subject": "Hi", "body": "Hello"}'
    try:
        handler.on_tool_start(serialized2, input_str2)
        result2 = send_email("alice@example.com", "Hi", "Hello")
        handler.on_tool_end(result2)
        print(f"    Result: {result2}")
    except PermissionError as exc:
        print(f"    BLOCKED: {exc}")

    # ── Also demo guarded_tool wrapper ───────────────────────────────────

    print("\n[3] Using guarded_tool() wrapper (same guard):")
    g_kb = guarded_tool(
        type("T", (), {"name": "knowledge_base_search", "description": "Search KB", "func": knowledge_base_search, "return_direct": False})(),
        guard,
    )
    g_email = guarded_tool(
        type("T", (), {"name": "send_email", "description": "Send email", "func": send_email, "return_direct": False})(),
        guard,
    )

    result3 = g_kb.func("neural networks")
    print(f"    knowledge_base_search via wrapper: {result3}")

    try:
        g_email.func("bob@example.com", "Test", "Body")
        print("    send_email via wrapper: executed (unexpected)")
    except PermissionError as exc:
        print(f"    send_email via wrapper BLOCKED: {exc}")

    # ── Receipts ─────────────────────────────────────────────────────────

    print("\n" + "=" * 60)
    print("Receipts written to:")
    print(f"  {receipts_path}")
    print()
    print("Verify with:")
    print(f"  idprova receipt verify {receipts_path}")
    print("=" * 60)

    # Show receipt contents
    print("\nReceipt log:")
    for i, line in enumerate(receipts_path.read_text().strip().splitlines()):
        print(f"  [{i}] {line}")


if __name__ == "__main__":
    main()
