"""IDProva CrewAI integration — scope-gated tools for ``crewai``.

Wraps a tool's function so that, before it executes, the call is checked
against the agent's granted scopes via :class:`~idprova_agents.guard.ToolGuard`.
Every call — allowed or denied — emits a signed, hash-chained receipt that
verifies with ``idprova receipt verify``.

The wrapped function is returned as a ``crewai`` ``Tool``, ready to register
with a CrewAI agent.
"""
from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Optional

from idprova_agents.guard import ToolGuard

logger = logging.getLogger(__name__)


def guarded_crewai_tool(
    func: Callable[..., Any],
    guard: ToolGuard,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    audit_only: bool = False,
) -> Any:
    """Wrap ``func`` as a scope-gated ``crewai`` ``Tool``.

    Before the function runs, the guard maps the tool to its required scope
    and checks it against the granted scopes.  If the scope is not granted:

    - ``audit_only=True`` — logs a warning, records ``"denied"``, still runs.
    - ``audit_only=False`` (default) — records ``"denied"`` and raises
      ``PermissionError`` (aborting the tool call).

    On success a ``"success"`` receipt is written; if the underlying function
    raises, an ``"error"`` receipt is written and the exception re-raised.

    Parameters
    ----------
    func :
        The tool implementation (sync). Its signature/type hints are preserved
        so CrewAI builds the correct tool schema.
    guard :
        A fully initialised :class:`ToolGuard`.
    name :
        Tool name (defaults to ``func.__name__``); also the key passed to
        ``guard.scope_for_tool``.
    description :
        Tool description (defaults to the function docstring).
    audit_only :
        Record but never block. Default ``False``.

    Returns
    -------
    crewai.tools.Tool
        A CrewAI Tool wrapping the guarded function.
    """
    # Imported lazily so importing this module doesn't require crewai.
    from crewai.tools import tool as crewai_tool

    tool_name = name or getattr(func, "__name__", "tool")

    @functools.wraps(func)
    def _guarded(*args: Any, **kwargs: Any) -> Any:
        # CrewAI invokes tools with keyword args; fall back to positional.
        if kwargs:
            tool_input: Any = kwargs
        elif len(args) == 1:
            tool_input = args[0]
        else:
            tool_input = list(args)

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

        try:
            result = func(*args, **kwargs)
        except Exception:
            guard.record(tool_name, tool_input, "error")
            raise

        guard.record(tool_name, tool_input, "success")
        return result

    built = crewai_tool(tool_name)(_guarded)
    if description:
        built.description = description
    return built
