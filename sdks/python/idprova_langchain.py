"""IDProva LangChain integration — audit callback handler."""
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional, Union

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
except ImportError:
    raise ImportError("langchain-core is required: pip install langchain-core")

from idprova_http import IDProvaClient


class IDProvaAuditCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that logs tool calls to IDProva receipts JSONL.

    Requires:
        - An active IDProva registry
        - A valid DAT token for the agent
        - A JSONL file path to write receipts

    Usage:
        handler = IDProvaAuditCallbackHandler(
            agent_did="did:idprova:example.com:myagent",
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

    def _sha256(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    def _write_receipt(self, tool_name: str, payload: dict, outcome: str) -> None:
        now = time.time()
        receipt = {
            "timestamp": now,
            "agent_did": self.agent_did,
            "tool": tool_name,
            "outcome": outcome,
            "payload_hash": self._sha256(json.dumps(payload, sort_keys=True)),
            "prev_hash": self._prev_hash,
        }
        receipt_str = json.dumps(receipt)
        self._prev_hash = self._sha256(receipt_str)
        with self.receipts_path.open("a") as f:
            f.write(receipt_str + "\n")

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        tool_name = serialized.get("name", "unknown")
        self._write_receipt(tool_name, {"input": input_str}, "start")

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        self._write_receipt("tool_end", {"output": output[:500]}, "success")

    def on_tool_error(self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any) -> None:
        self._write_receipt("tool_error", {"error": str(error)}, "error")
