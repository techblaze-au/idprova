"""IDProva Agents — verifiable, scope-gated tool execution for AI agent frameworks.

Exports
-------
ToolGuard      Core guard: scope check + receipt emission.
Decision       Result of a scope check (allowed + reason).
guarded_tool   LangChain tool wrapper with hard enforcement.
IDProvaGuardCallbackHandler  LangChain callback handler (enforce + audit).
"""
from idprova_agents.guard import Decision, ToolGuard
from idprova_agents.langchain_adapter import (
    IDProvaGuardCallbackHandler,
    guarded_tool,
)

__all__ = [
    "Decision",
    "ToolGuard",
    "IDProvaGuardCallbackHandler",
    "guarded_tool",
]
