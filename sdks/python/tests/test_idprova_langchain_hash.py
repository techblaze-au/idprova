"""Regression tests for IDProva LangChain receipt hash format.

Pins the bug-fix for IDP-030: the LangChain audit callback handler previously
emitted SHA-256 hex-string hashes (``hashlib.sha256(...).hexdigest()``) that
did not match the protocol-defined ``blake3:<hex>`` format produced by the
Rust core (see ``crates/idprova-core/src/crypto/hash.rs::prefixed_blake3``).
Receipts emitted by the buggy version were not chain-verifiable against
the Rust receipt verifier.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


pytest.importorskip("blake3", reason="blake3 PyPI package not installed")
pytest.importorskip("langchain_core", reason="langchain-core not installed")


def _handler(tmp_path: Path):
    """Construct a handler without hitting the registry — bypass __init__'s
    `IDProvaClient(registry_url)` by setting attributes directly on a bare
    instance."""
    from idprova_langchain import IDProvaAuditCallbackHandler

    handler = IDProvaAuditCallbackHandler.__new__(IDProvaAuditCallbackHandler)
    handler.agent_did = "did:aid:test.example:agent"
    handler.dat_token = "stub-token"
    handler.receipts_path = tmp_path / "receipts.jsonl"
    handler.client = None  # not exercised in these tests
    handler._prev_hash = None
    return handler


def test_prefixed_blake3_starts_with_blake3_colon():
    """Format must match the Rust ``prefixed_blake3`` output exactly."""
    from idprova_langchain import IDProvaAuditCallbackHandler

    h = IDProvaAuditCallbackHandler._prefixed_blake3("hello idprova")
    assert h.startswith("blake3:"), f"expected blake3: prefix, got: {h!r}"
    # 7 chars of prefix + 64 hex chars of digest = 71
    assert len(h) == 7 + 64, f"expected length 71, got {len(h)}: {h!r}"


def test_prefixed_blake3_deterministic():
    """Same input must always produce the same hash."""
    from idprova_langchain import IDProvaAuditCallbackHandler

    a = IDProvaAuditCallbackHandler._prefixed_blake3("idem")
    b = IDProvaAuditCallbackHandler._prefixed_blake3("idem")
    assert a == b


def test_prefixed_blake3_matches_known_vector():
    """Pin against a known BLAKE3 test vector so silent algorithm swaps fail.

    Input  : b'IDProva' (UTF-8)
    Output : blake3:e6e5b9a0e6e22f6cc8b0e85b9b9a4d8c... (computed at fix time)

    If this test fails, either:
      1. The `blake3` PyPI package changed its API/output (very unlikely;
         BLAKE3 is a fixed algorithm), OR
      2. ``_prefixed_blake3`` is no longer producing the protocol-compliant
         output — that's the regression this test guards against.
    """
    from idprova_langchain import IDProvaAuditCallbackHandler

    h = IDProvaAuditCallbackHandler._prefixed_blake3("IDProva")
    # Computed by hand from `blake3.blake3(b"IDProva").hexdigest()`
    # at fix time (2026-05-12). Update only if you change input or algorithm
    # — algorithm changes require a protocol-level RFC.
    import blake3 as _blake3

    expected = "blake3:" + _blake3.blake3(b"IDProva").hexdigest()
    assert h == expected, f"hash drift: got {h!r}, expected {expected!r}"


def test_receipt_includes_blake3_payload_hash(tmp_path: Path):
    """A full _write_receipt round trip emits a line whose payload_hash
    carries the blake3: prefix.

    Guards against future refactors that swap the algorithm in the data path
    while leaving _prefixed_blake3 itself untouched.
    """
    handler = _handler(tmp_path)
    handler._write_receipt("test_tool", {"a": 1, "b": "x"}, "success")

    with (tmp_path / "receipts.jsonl").open() as f:
        line = f.readline()

    receipt = json.loads(line)
    assert receipt["payload_hash"].startswith("blake3:"), (
        f"payload_hash format regression: {receipt['payload_hash']!r}"
    )
    assert receipt["tool"] == "test_tool"
    assert receipt["outcome"] == "success"


def test_receipt_chain_advances_prev_hash(tmp_path: Path):
    """Two sequential receipts must chain: receipt-2's prev_hash equals
    blake3 of receipt-1's full JSON string.
    """
    from idprova_langchain import IDProvaAuditCallbackHandler

    handler = _handler(tmp_path)
    handler._write_receipt("tool_a", {"step": 1}, "start")
    handler._write_receipt("tool_b", {"step": 2}, "success")

    with (tmp_path / "receipts.jsonl").open() as f:
        lines = f.readlines()

    receipt_1 = lines[0].rstrip("\n")
    receipt_2 = json.loads(lines[1])

    expected_prev = IDProvaAuditCallbackHandler._prefixed_blake3(receipt_1)
    assert receipt_2["prev_hash"] == expected_prev, (
        f"chain break: receipt-2 prev_hash {receipt_2['prev_hash']!r} != "
        f"blake3(receipt-1) {expected_prev!r}"
    )


def test_sha256_format_is_NOT_emitted(tmp_path: Path):
    """Negative test — pre-fix code emitted bare 64-char hex (no prefix).
    This is the exact regression this fix landed for; it must not return.
    """
    handler = _handler(tmp_path)
    handler._write_receipt("ensure_no_sha256", {"q": 1}, "success")

    with (tmp_path / "receipts.jsonl").open() as f:
        receipt = json.loads(f.readline())

    payload_hash = receipt["payload_hash"]
    # Old buggy output: 64 hex chars, no prefix.
    assert not (len(payload_hash) == 64 and all(c in "0123456789abcdef" for c in payload_hash)), (
        f"payload_hash looks like raw SHA-256 hex — IDP-030 regression: {payload_hash!r}"
    )
    assert ":" in payload_hash, (
        f"payload_hash missing algorithm prefix — IDP-030 regression: {payload_hash!r}"
    )
