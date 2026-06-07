"""IDProva LangChain integration — audit + enforce callback handlers.

Two callback handlers are provided:

- ``IDProvaAuditCallbackHandler`` — original audit-only handler (legacy).
- ``IDProvaGuardCallbackHandler`` — scope-gated enforcement via ToolGuard
  (in ``idprova_agents.langchain_adapter``).

Receipts emitted by the audit handler use BLAKE3 with the algorithm-prefix
format ``blake3:<64-hex>``, matching the Rust core (see
``crates/idprova-core/src/crypto/hash.rs::prefixed_blake3``). Pre-2026-05
revisions of this file used SHA-256 hex without a prefix; receipts emitted
by those revisions are incompatible with the protocol's hash-chain
verifier and must be regenerated.
"""
import json
import time
from pathlib import Path
from typing import Any, Optional, Union

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
except ImportError:
    raise ImportError("langchain-core is required: pip install langchain-core")

try:
    import blake3 as _blake3
except ImportError:
    raise ImportError(
        "blake3 is required for IDProva receipt hashing: pip install blake3"
    )

from idprova_http import IDProvaClient


class IDProvaAuditCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that logs tool calls to IDProva receipts JSONL.

    Requires:
        - An active IDProva registry
        - A valid DAT token for the agent
        - A JSONL file path to write receipts

    Usage:
        handler = IDProvaAuditCallbackHandler(
            agent_did="did:aid:example.com:myagent",
            dat_token="...",
            receipts_path="receipts.jsonl",
        )
        llm = ChatOpenAI(callbacks=[handler])
    """

    def __init__(
        self,
        agent_did: str,
        dat_token: str,
        receipts_path: Union[str, Path] = "receipts.jsonl",
        registry_url: str = "http://localhost:3000",
    ):
        self.agent_did = agent_did
        self.dat_token = dat_token
        self.receipts_path = Path(receipts_path)
        self.client = IDProvaClient(registry_url)
        self._prev_hash: Optional[str] = None

    @staticmethod
    def _prefixed_blake3(data: str) -> str:
        """BLAKE3 hash of ``data`` formatted as ``blake3:<64-hex>``.

        Matches ``idprova_core::crypto::hash::prefixed_blake3`` so receipts
        produced by this Python handler chain-verify against receipts
        produced by the Rust core or any other IDProva SDK.
        """
        return "blake3:" + _blake3.blake3(data.encode()).hexdigest()

    def _write_receipt(self, tool_name: str, payload: dict, outcome: str) -> None:
        now = time.time()
        receipt = {
            "timestamp": now,
            "agent_did": self.agent_did,
            "tool": tool_name,
            "outcome": outcome,
            "payload_hash": self._prefixed_blake3(json.dumps(payload, sort_keys=True)),
            "prev_hash": self._prev_hash,
        }
        receipt_str = json.dumps(receipt)
        self._prev_hash = self._prefixed_blake3(receipt_str)
        with self.receipts_path.open("a") as f:
            f.write(receipt_str + "\n")

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        tool_name = serialized.get("name", "unknown")
        self._write_receipt(tool_name, {"input": input_str}, "start")

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        self._write_receipt("tool_end", {"output": output[:500]}, "success")

    def on_tool_error(self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any) -> None:
        self._write_receipt("tool_error", {"error": str(error)}, "error")


# ── Backward-compat re-exports from the enforce+audit adapter ─────────────
from idprova_agents.langchain_adapter import (  # noqa: E402
    IDProvaGuardCallbackHandler,
    guarded_tool,
)

__all__ = [
    "IDProvaAuditCallbackHandler",
    "IDProvaGuardCallbackHandler",
    "guarded_tool",
]
