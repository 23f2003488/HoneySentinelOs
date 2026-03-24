"""
Memory package.
Import get_memory_store() everywhere — never instantiate a store directly.
"""

import os
from .store import LocalMemoryStore, MemoryStore
from .models import (
    AgentState, AgentStatus, Finding, HITLQuestion, HITLStatus,
    RepoMap, FileNode, SessionMeta, SessionStatus, ToolResult, Severity, _now,
)

_store_instance: MemoryStore | None = None


def get_memory_store() -> MemoryStore:
    """
    Singleton factory. Returns LocalMemoryStore by default.
    When MEMORY_BACKEND=cosmos is set (Phase 3), returns CosmosMemoryStore.
    """
    global _store_instance
    if _store_instance is not None:
        return _store_instance

    backend = os.getenv("MEMORY_BACKEND", "local").lower()

    if backend == "cosmos":
        from .cosmos_store import CosmosMemoryStore  # imported lazily
        _store_instance = CosmosMemoryStore()
    else:
        _store_instance = LocalMemoryStore()

    return _store_instance


def reset_store() -> None:
    """Reset singleton — used in tests only."""
    global _store_instance
    _store_instance = None


__all__ = [
    "get_memory_store", "reset_store", "MemoryStore", "LocalMemoryStore",
    "AgentState", "AgentStatus", "Finding", "HITLQuestion", "HITLStatus",
    "RepoMap", "FileNode", "SessionMeta", "SessionStatus", "ToolResult",
    "Severity", "_now",
]
