"""IDProva LangChain integration — enforce + audit callback handler.

Wraps ``ToolGuard`` to gate LangChain tool calls against DAT scopes.
Every call — allowed or denied — emits a verifiable receipt to the
JSONL receipts file.

Backward-compatible audit-only handler is in ``idprova_langchain.py``
(re-exported here for convenience).
"""
from __future__ import annotations

import logging
from typing import Any, Optional, Union

from idprova_agents.guard import Decision, ToolGuard

logger = logging.getLogger(__name__)


class _ToolCallTracker:
    """Tracks in-flight tool call metadata for receipt recording."""

    def __init__(self, tool_name: str, tool_input: Any) -> None:
        self.tool_name = tool_name
        self.tool_input = tool_input


class IDProvaGuardCallbackHandler:
    """LangChain callback handler that enforces scope gates via ToolGuard.

    On ``on_tool_start`` the handler calls ``guard.check()``.  If the scope
    is not granted:

    - ``audit_only=True`` — logs a warning, records ``"denied"``, continues.
    - ``audit_only=False`` (default) — records ``"denied"`` and raises
      ``PermissionError`` to abort the agent loop.

    Parameters
    ----------
    guard : ToolGuard
        A fully initialised guard (with signing key, scopes, etc.).
    audit_only : bool
        When ``True``, record but never raise.  Default ``False``.
    """

    def __init__(
        self,
        guard: ToolGuard,
        *,
        audit_only: bool = False,
    ) -> None:
        self.guard = guard
        self.audit_only = audit_only
        self._current: Optional[_ToolCallTracker] = None

    # ── LangChain callback interface ──────────────────────────────────────

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown")
        decision: Decision = self.guard.check(tool_name, input_str)

        if not decision.allowed:
            self.guard.record(tool_name, input_str, "denied")
            if self.audit_only:
                logger.warning(
                    "AUDIT-ONLY: tool %s DENIED — %s", tool_name, decision.reason
                )
            else:
                raise PermissionError(
                    f"Tool '{tool_name}' denied by IDProva scope gate: {decision.reason}"
                )

        self._current = _ToolCallTracker(tool_name, input_str)

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        if self._current is not None:
            self.guard.record(self._current.tool_name, self._current.tool_input, "success")
            self._current = None

    def on_tool_error(
        self,
        error: Union[BaseException, KeyboardInterrupt],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        if self._current is not None:
            self.guard.record(
                self._current.tool_name, self._current.tool_input, "error"
            )
            self._current = None


def guarded_tool(
    tool: Any,
    guard: ToolGuard,
    *,
    audit_only: bool = False,
) -> Any:
    """Wrap a LangChain ``Tool`` so its ``func`` is scope-gated.

    The wrapped function calls ``guard.check()`` before executing.
    If the scope is not granted:

    - ``audit_only=True`` — logs a warning, records ``"denied"``, still executes.
    - ``audit_only=False`` (default) — records ``"denied"`` and raises
      ``PermissionError``.

    Parameters
    ----------
    tool : Tool
        A LangChain ``Tool`` instance (must have ``.name``, ``.func``, ``.description``).
    guard : ToolGuard
        A fully initialised guard.
    audit_only : bool
        When ``True``, record but still execute.  Default ``False``.

    Returns
    -------
    Tool
        A new ``Tool`` wrapping the original with enforcement.
    """
    original_func = tool.func
    tool_name = tool.name

    def _guarded_func(*args: Any, **kwargs: Any) -> Any:
        tool_input = kwargs or (args[0] if args else {})
        decision = guard.check(tool_name, tool_input)

        if not decision.allowed:
            guard.record(tool_name, tool_input, "denied")
            if audit_only:
                logger.warning(
                    "AUDIT-ONLY: tool %s DENIED — %s", tool_name, decision.reason
                )
            else:
                raise PermissionError(
                    f"Tool '{tool_name}' denied by IDProva scope gate: {decision.reason}"
                )

        guard.record(tool_name, tool_input, "success")
        return original_func(*args, **kwargs)

    # Import here to avoid hard dep at module level when langchain isn't installed.
    from langchain_core.tools import Tool

    return Tool(
        name=tool.name,
        description=tool.description,
        func=_guarded_func,
        return_direct=tool.return_direct,
    )
