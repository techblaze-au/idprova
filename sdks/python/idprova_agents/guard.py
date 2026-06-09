"""IDProva Agents — ToolGuard: scope-gated tool execution with verifiable receipts.

The receipt serializer here is byte-exact against the Rust ``Receipt`` /
``ReceiptLog::verify_integrity`` in ``crates/idprova-core/src/receipt/``.
Every JSON byte fed to BLAKE3 must be identical to what ``serde_json::to_vec``
produces for the same logical receipt — the hash chain verifier accepts
nothing less.

See ``GUARD_CONTRACT.md`` §1–§3 for the locked specification.
"""
from __future__ import annotations

import json
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, List, Optional, Union

try:
    import blake3 as _blake3
except ImportError:
    raise ImportError(
        "blake3 is required for IDProva receipt hashing: pip install blake3"
    )

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
except ImportError:
    raise ImportError(
        "cryptography is required for Ed25519 signing: pip install cryptography"
    )


# ── §1  Receipt serializer (byte-exact against Rust serde_json) ──────────


def _format_timestamp(dt: datetime) -> str:
    """Format a datetime the way chrono's ``DateTime<Utc>`` serialises in serde_json.

    Chrono behaviour:
    - No fractional seconds → ``2026-06-08T00:00:00Z``
    - With fractional seconds → ``2026-06-08T12:34:56.123456Z`` (6 digits,
      no trailing-zero trim — chrono uses ``Fixed`` internally for serde)

    Python's ``datetime.isoformat()`` produces the same shape when the
    microsecond component is present (6 digits, no trailing zeros) and
    omits the fractional part entirely when ``microsecond == 0``.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt_utc = dt.astimezone(timezone.utc)
    base = dt_utc.strftime("%Y-%m-%dT%H:%M:%S")
    us = dt_utc.microsecond
    if us:
        return f"{base}.{us:06d}Z"
    return f"{base}Z"


def _prefixed_blake3(data: bytes) -> str:
    """BLAKE3 hash formatted as ``blake3:<64-hex>``.

    Matches ``idprova_core::crypto::hash::prefixed_blake3``.
    """
    return "blake3:" + _blake3.blake3(data).hexdigest()


def _build_action_dict(
    action_type: str,
    input_hash: str,
    status: str,
    tool: Optional[str] = None,
    output_hash: Optional[str] = None,
    duration_ms: Optional[int] = None,
    server: Optional[str] = None,
) -> OrderedDict:
    """Build an action dict with fields in Rust ``ActionDetails`` declaration order.

    Serde serialises struct fields in declaration order.  ``ActionDetails``
    is declared: ``action_type`` (→ "type"), ``server``, ``tool``,
    ``input_hash`` (→ "inputHash"), ``output_hash`` (→ "outputHash"),
    ``status``, ``duration_ms`` (→ "durationMs").  Optional fields are
    skipped when ``None`` (``skip_serializing_if = "Option::is_none"``).
    """
    d: OrderedDict[str, Any] = OrderedDict()
    d["type"] = action_type
    if server is not None:
        d["server"] = server
    if tool is not None:
        d["tool"] = tool
    d["inputHash"] = input_hash
    if output_hash is not None:
        d["outputHash"] = output_hash
    d["status"] = status
    if duration_ms is not None:
        d["durationMs"] = duration_ms
    return d


def _build_chain_dict(previous_hash: str, sequence_number: int) -> OrderedDict:
    """Build a chain-link dict matching Rust ``ChainLink`` field order."""
    return OrderedDict([
        ("previousHash", previous_hash),
        ("sequenceNumber", sequence_number),
    ])


def receipt_to_json(receipt: dict) -> str:
    """Serialize a receipt dict to the exact JSON wire format.

    Compact separators (``separators=(",",":")``), raw UTF-8
    (``ensure_ascii=False``), keys already in insertion order.
    """
    return json.dumps(receipt, separators=(",", ":"), ensure_ascii=False)


def signing_payload_bytes(receipt: dict) -> bytes:
    """Compute the signing-payload bytes for a receipt.

    Mirrors ``Receipt::signing_payload_bytes()`` in Rust: a JSON object with
    fields ``id, timestamp, agent, dat, [kind], action, [context], chain``
    in that exact order, **excluding** ``signature`` and ``anchor``.

    ``kind`` is omitted when it equals ``"data"`` (the default), matching
    ``#[serde(default, skip_serializing_if = "ReceiptKind::is_data")]``.
    ``context`` is omitted when ``None``, matching
    ``#[serde(skip_serializing_if = "Option::is_none")]``.
    """
    payload: OrderedDict[str, Any] = OrderedDict()
    payload["id"] = receipt["id"]
    payload["timestamp"] = receipt["timestamp"]
    payload["agent"] = receipt["agent"]
    payload["dat"] = receipt["dat"]
    kind = receipt.get("kind")
    if kind is not None and kind != "data":
        payload["kind"] = receipt["kind"]
    payload["action"] = receipt["action"]
    ctx = receipt.get("context")
    if ctx is not None:
        payload["context"] = ctx
    payload["chain"] = receipt["chain"]
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── §3  Decision ─────────────────────────────────────────────────────────


@dataclass
class Decision:
    """Result of a scope check."""
    allowed: bool
    reason: str


# ── §3  Scope check (mirrors ScopeSet::permits) ──────────────────────────


def _parse_scope(s: str) -> tuple[str, str, str, str]:
    """Parse a 4-part scope string ``namespace:protocol:resource:action``.

    Raises ``ValueError`` if the string does not have exactly 4 parts.
    """
    parts = s.split(":")
    if len(parts) != 4:
        raise ValueError(
            f"scope must have 4 parts (namespace:protocol:resource:action), got: {s}"
        )
    return (parts[0], parts[1], parts[2], parts[3])


def _scope_covers(
    granted: tuple[str, str, str, str],
    required: tuple[str, str, str, str],
) -> bool:
    """Check if a granted scope covers a required scope.

    Each component matches if it is equal or is the wildcard ``"*"``.
    Mirrors ``Scope::covers()`` in Rust.
    """
    return all(
        g == "*" or g == r for g, r in zip(granted, required)
    )


def _check_scope(required_scope: str, granted_scopes: list[str]) -> Decision:
    """Allow iff ``required_scope`` is covered by at least one granted scope.

    Mirrors ``ScopeSet::permits()`` in Rust.
    """
    req = _parse_scope(required_scope)
    for gs in granted_scopes:
        granted = _parse_scope(gs)
        if _scope_covers(granted, req):
            return Decision(True, f"scope '{required_scope}' granted")
    return Decision(
        False,
        f"scope '{required_scope}' not in granted scopes {granted_scopes}",
    )


# ── §3  ToolGuard ────────────────────────────────────────────────────────


class ToolGuard:
    """Offline scope-gated tool guard with verifiable receipt emission.

    Parameters
    ----------
    aid : str
        Agent AID (e.g. ``"did:aid:co:researcher"``).
    dat : str
        DAT token or ID the agent is operating under.
    signing_key : Ed25519PrivateKey
        Agent's Ed25519 private key for receipt signing.
    scope_for_tool : Callable[[str], str]
        Maps a tool name to the required scope string.
    granted_scopes : list[str]
        Scopes parsed from the DAT.
    receipts_path : str | Path
        Path to the JSONL receipts file.
    """

    def __init__(
        self,
        aid: str,
        dat: str,
        signing_key: Ed25519PrivateKey,
        scope_for_tool: Callable[[str], str],
        granted_scopes: List[str],
        receipts_path: Union[str, Path],
    ) -> None:
        self.aid = aid
        self.dat = dat
        self.signing_key = signing_key
        self.scope_for_tool = scope_for_tool
        self.granted_scopes = granted_scopes
        self.receipts_path = Path(receipts_path)
        self._prev_hash: Optional[str] = None
        self._sequence: int = 0
        # Clear the file on init so each run starts fresh.
        self.receipts_path.write_text("", encoding="utf-8")

    def check(self, tool_name: str, tool_input: Any) -> Decision:
        """Map tool → required scope; allow iff covered by granted scopes."""
        required_scope = self.scope_for_tool(tool_name)
        return _check_scope(required_scope, self.granted_scopes)

    def record(self, tool_name: str, tool_input: Any, status: str) -> None:
        """Append ONE receipt (schema §1, chain §2) for this call.

        Both allow and deny are recorded — accountability covers refusals.
        """
        input_bytes = json.dumps(
            tool_input, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        input_hash = _prefixed_blake3(input_bytes)

        previous_hash = self._prev_hash if self._prev_hash else "genesis"
        seq = self._sequence

        action = _build_action_dict(
            action_type="tool_call",
            input_hash=input_hash,
            status=status,
            tool=tool_name,
        )
        chain = _build_chain_dict(previous_hash, seq)

        receipt: OrderedDict[str, Any] = OrderedDict()
        receipt["id"] = str(uuid.uuid4())
        receipt["timestamp"] = _format_timestamp(datetime.now(timezone.utc))
        receipt["agent"] = self.aid
        receipt["dat"] = self.dat
        # kind omitted — this is always a Data receipt (v0.1 wire compat).
        receipt["action"] = action
        # context omitted — None (v0.1 wire compat).
        receipt["chain"] = chain

        payload = signing_payload_bytes(receipt)
        sig = self.signing_key.sign(payload)
        receipt["signature"] = sig.hex()

        line = receipt_to_json(receipt) + "\n"
        with self.receipts_path.open("a", encoding="utf-8") as f:
            f.write(line)

        self._prev_hash = _prefixed_blake3(payload)
        self._sequence = seq + 1
