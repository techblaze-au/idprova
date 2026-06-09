"""Tests for the IDProva AutoGen integration.

Covers:
  - In-scope tool call allowed + "success" receipt
  - Out-of-scope tool call blocked (raises) + "denied" receipt
  - Receipt chain integrity (previousHash of entry 1 == blake3 of entry 0)
  - audit_only mode records but does not block
  - Optional: ``idprova receipt verify`` if the binary is on PATH
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from autogen_core import CancellationToken

from idprova_agents.guard import ToolGuard, signing_payload_bytes, _prefixed_blake3
from idprova_agents.autogen_adapter import guarded_function_tool


SCOPE_MAP = {
    "knowledge_base_search": "mcp:tool:knowledge-base:read",
    "send_email": "mcp:tool:email:send",
}
GRANTED_SCOPES = ["mcp:tool:knowledge-base:read"]


def knowledge_base_search(query: str) -> str:
    """Search the internal knowledge base."""
    return f"Results for '{query}'"


def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return f"Email sent to {to}"


def _run(coro):
    return asyncio.run(coro)


def _read_receipts(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


@pytest.fixture()
def guard(tmp_path: Path) -> ToolGuard:
    return ToolGuard(
        aid="did:aid:co:researcher",
        dat="dat-test-001",
        signing_key=Ed25519PrivateKey.generate(),
        scope_for_tool=lambda name: SCOPE_MAP.get(name, "mcp:tool:unknown:none"),
        granted_scopes=GRANTED_SCOPES,
        receipts_path=tmp_path / "receipts.jsonl",
    )


class TestAutogenGuard:
    def test_in_scope_tool_allowed_and_receipt_recorded(self, guard: ToolGuard) -> None:
        tool = guarded_function_tool(knowledge_base_search, guard)
        result = _run(tool.run_json({"query": "quantum"}, CancellationToken()))
        assert "quantum" in tool.return_value_as_string(result)

        receipts = _read_receipts(guard.receipts_path)
        assert len(receipts) == 1
        r = receipts[0]
        assert r["action"]["tool"] == "knowledge_base_search"
        assert r["action"]["status"] == "success"
        assert r["chain"]["sequenceNumber"] == 0
        assert r["chain"]["previousHash"] == "genesis"
        assert "signature" in r

    def test_out_of_scope_tool_blocked_and_denied_receipt_recorded(
        self, guard: ToolGuard
    ) -> None:
        tool = guarded_function_tool(send_email, guard)
        with pytest.raises(PermissionError, match="send_email.*denied"):
            _run(tool.run_json(
                {"to": "alice@example.com", "subject": "Hi", "body": "Hello"},
                CancellationToken(),
            ))

        receipts = _read_receipts(guard.receipts_path)
        assert len(receipts) == 1
        r = receipts[0]
        assert r["action"]["tool"] == "send_email"
        assert r["action"]["status"] == "denied"
        assert "signature" in r

    def test_two_calls_produce_two_receipts_with_valid_chain(
        self, guard: ToolGuard
    ) -> None:
        kb = guarded_function_tool(knowledge_base_search, guard)
        email = guarded_function_tool(send_email, guard)

        _run(kb.run_json({"query": "q1"}, CancellationToken()))
        with pytest.raises(PermissionError):
            _run(email.run_json(
                {"to": "a", "subject": "s", "body": "b"}, CancellationToken()
            ))

        receipts = _read_receipts(guard.receipts_path)
        assert len(receipts) == 2
        assert receipts[0]["action"]["status"] == "success"
        assert receipts[1]["action"]["status"] == "denied"
        assert receipts[1]["chain"]["sequenceNumber"] == 1

        payload0 = signing_payload_bytes(receipts[0])
        expected_prev_hash = _prefixed_blake3(payload0)
        assert receipts[1]["chain"]["previousHash"] == expected_prev_hash

    def test_audit_only_does_not_raise(self, guard: ToolGuard) -> None:
        tool = guarded_function_tool(send_email, guard, audit_only=True)
        _run(tool.run_json(
            {"to": "a", "subject": "s", "body": "b"}, CancellationToken()
        ))

        receipts = _read_receipts(guard.receipts_path)
        assert len(receipts) == 2  # denied + success
        assert receipts[0]["action"]["status"] == "denied"
        assert receipts[1]["action"]["status"] == "success"


@pytest.mark.skipif(
    not shutil.which("idprova"),
    reason="idprova binary not on PATH — skipping CLI verification",
)
def test_receipt_verify_cli(tmp_path: Path) -> None:
    guard = ToolGuard(
        aid="did:aid:co:researcher",
        dat="dat-test-cli",
        signing_key=Ed25519PrivateKey.generate(),
        scope_for_tool=lambda name: SCOPE_MAP.get(name, "mcp:tool:unknown:none"),
        granted_scopes=GRANTED_SCOPES,
        receipts_path=tmp_path / "receipts.jsonl",
    )
    kb = guarded_function_tool(knowledge_base_search, guard)
    email = guarded_function_tool(send_email, guard)
    _run(kb.run_json({"query": "q"}, CancellationToken()))
    with pytest.raises(PermissionError):
        _run(email.run_json({"to": "a", "subject": "s", "body": "b"}, CancellationToken()))

    result = subprocess.run(
        ["idprova", "receipt", "verify", str(guard.receipts_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"verify failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
