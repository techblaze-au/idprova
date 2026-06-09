"""Tests for the IDProva LangChain integration.

Covers:
  - In-scope tool call allowed + "success" receipt
  - Out-of-scope tool call blocked (raises) + "denied" receipt
  - Receipt chain integrity (previousHash of entry 1 == blake3 of entry 0)
  - Optional: ``idprova receipt verify`` if the binary is on PATH
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from idprova_agents.guard import ToolGuard, signing_payload_bytes, _prefixed_blake3
from idprova_agents.langchain_adapter import IDProvaGuardCallbackHandler


# ── Fixtures ──────────────────────────────────────────────────────────────

SCOPE_MAP = {
    "knowledge_base_search": "mcp:tool:knowledge-base:read",
    "send_email": "mcp:tool:email:send",
}

GRANTED_SCOPES = ["mcp:tool:knowledge-base:read"]


@pytest.fixture()
def guard(tmp_path: Path) -> ToolGuard:
    """Create a ToolGuard with a fresh Ed25519 key and temp receipts file."""
    return ToolGuard(
        aid="did:aid:co:researcher",
        dat="dat-test-001",
        signing_key=Ed25519PrivateKey.generate(),
        scope_for_tool=lambda name: SCOPE_MAP.get(name, "mcp:tool:unknown:none"),
        granted_scopes=GRANTED_SCOPES,
        receipts_path=tmp_path / "receipts.jsonl",
    )


@pytest.fixture()
def handler(guard: ToolGuard) -> IDProvaGuardCallbackHandler:
    """Create a callback handler backed by the guard."""
    return IDProvaGuardCallbackHandler(guard)


# ── Tests ─────────────────────────────────────────────────────────────────


class TestGuardCallback:
    """Scope enforcement via the callback handler."""

    def test_in_scope_tool_allowed_and_receipt_recorded(
        self, handler: IDProvaGuardCallbackHandler, guard: ToolGuard
    ) -> None:
        """In-scope call: no exception, tool executes, 'success' receipt written."""
        serialized = {"name": "knowledge_base_search"}
        input_str = "quantum computing"

        # Should NOT raise
        handler.on_tool_start(serialized, input_str)
        handler.on_tool_end("search results here")

        # Verify receipt
        receipts = _read_receipts(guard.receipts_path)
        assert len(receipts) == 1
        r = receipts[0]
        assert r["action"]["tool"] == "knowledge_base_search"
        assert r["action"]["status"] == "success"
        assert r["chain"]["sequenceNumber"] == 0
        assert r["chain"]["previousHash"] == "genesis"
        assert "signature" in r

    def test_out_of_scope_tool_blocked_and_denied_receipt_recorded(
        self, handler: IDProvaGuardCallbackHandler, guard: ToolGuard
    ) -> None:
        """Out-of-scope call: PermissionError raised, 'denied' receipt written."""
        serialized = {"name": "send_email"}
        input_str = '{"to": "alice@example.com", "subject": "Hi", "body": "Hello"}'

        with pytest.raises(PermissionError, match="send_email.*denied"):
            handler.on_tool_start(serialized, input_str)

        # Verify denied receipt
        receipts = _read_receipts(guard.receipts_path)
        assert len(receipts) == 1
        r = receipts[0]
        assert r["action"]["tool"] == "send_email"
        assert r["action"]["status"] == "denied"
        assert r["chain"]["sequenceNumber"] == 0
        assert "signature" in r

    def test_two_calls_produce_two_receipts_with_valid_chain(
        self, handler: IDProvaGuardCallbackHandler, guard: ToolGuard
    ) -> None:
        """Both tools called sequentially; receipts.jsonl has 2 entries with valid chain."""
        # Call 1: allowed
        handler.on_tool_start({"name": "knowledge_base_search"}, "q1")
        handler.on_tool_end("result")

        # Call 2: blocked
        with pytest.raises(PermissionError):
            handler.on_tool_start({"name": "send_email"}, "email payload")

        receipts = _read_receipts(guard.receipts_path)
        assert len(receipts) == 2

        # Entry 0: success, genesis chain
        r0 = receipts[0]
        assert r0["action"]["status"] == "success"
        assert r0["chain"]["previousHash"] == "genesis"
        assert r0["chain"]["sequenceNumber"] == 0

        # Entry 1: denied, chain links to entry 0
        r1 = receipts[1]
        assert r1["action"]["status"] == "denied"
        assert r1["chain"]["sequenceNumber"] == 1

        # Verify chain: previousHash of entry 1 == prefixed blake3 of entry 0's signing payload
        payload0 = signing_payload_bytes(r0)
        expected_prev_hash = _prefixed_blake3(payload0)
        assert r1["chain"]["previousHash"] == expected_prev_hash, (
            f"Chain broken: expected {expected_prev_hash}, got {r1['chain']['previousHash']}"
        )

    def test_audit_only_does_not_raise(
        self, guard: ToolGuard
    ) -> None:
        """In audit_only mode, out-of-scope call records but does NOT raise."""
        handler = IDProvaGuardCallbackHandler(guard, audit_only=True)

        # Should NOT raise
        handler.on_tool_start({"name": "send_email"}, "payload")
        handler.on_tool_end("sent")

        receipts = _read_receipts(guard.receipts_path)
        assert len(receipts) == 2  # denied + success
        assert receipts[0]["action"]["status"] == "denied"
        assert receipts[1]["action"]["status"] == "success"


@pytest.mark.skipif(
    not shutil.which("idprova"),
    reason="idprova binary not on PATH — skipping CLI verification",
)
def test_receipt_verify_cli(tmp_path: Path) -> None:
    """Shell out to ``idprova receipt verify`` if the binary is available."""
    guard = ToolGuard(
        aid="did:aid:co:researcher",
        dat="dat-test-cli",
        signing_key=Ed25519PrivateKey.generate(),
        scope_for_tool=lambda name: SCOPE_MAP.get(name, "mcp:tool:unknown:none"),
        granted_scopes=GRANTED_SCOPES,
        receipts_path=tmp_path / "receipts.jsonl",
    )
    handler = IDProvaGuardCallbackHandler(guard)

    # Generate two receipts
    handler.on_tool_start({"name": "knowledge_base_search"}, "q")
    handler.on_tool_end("r")
    with pytest.raises(PermissionError):
        handler.on_tool_start({"name": "send_email"}, "e")

    result = subprocess.run(
        ["idprova", "receipt", "verify", str(guard.receipts_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"idprova receipt verify failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "VALID" in result.stdout.upper() or result.returncode == 0


# ── Helpers ───────────────────────────────────────────────────────────────


def _read_receipts(path: Path) -> list[dict]:
    """Read a JSONL receipts file into a list of dicts."""
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]
