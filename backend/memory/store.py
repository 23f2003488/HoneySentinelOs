"""
HoneySentinel-OS — Memory Store
Defines the abstract interface and a local (in-process) implementation.
CosmosMemoryStore will be added in Phase 3 and swapped in via env var MEMORY_BACKEND=cosmos.

All agents call MemoryStore methods — never touch raw dicts or each other.
Every write emits a change event that the WebSocket layer can forward to the UI.
"""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any, Callable, Optional

from .models import (
    AgentState, AgentStatus, Finding, HITLQuestion, HITLStatus,
    RepoMap, SessionMeta, SessionStatus, ToolResult, _now,
)

logger = logging.getLogger(__name__)


# ─── Change Event ─────────────────────────────────────────────────────────────

class ChangeEvent:
    """Emitted on every write so the WebSocket layer can stream it to the UI."""
    def __init__(self, namespace: str, key: str, data: dict):
        self.namespace = namespace   # "agent_state" | "finding" | "hitl" | "session" | "tool_result"
        self.key = key               # agent_id, finding_id etc
        self.data = data
        self.timestamp = _now()

    def to_dict(self) -> dict:
        return {
            "namespace": self.namespace,
            "key": self.key,
            "data": self.data,
            "timestamp": self.timestamp,
        }


# ─── Abstract Interface ────────────────────────────────────────────────────────

class MemoryStore(ABC):
    """
    All agents talk to this interface.
    Concrete implementations: LocalMemoryStore, CosmosMemoryStore.
    """

    def __init__(self):
        self._listeners: list[Callable[[ChangeEvent], Any]] = []

    def subscribe(self, callback: Callable[[ChangeEvent], Any]) -> None:
        """Register a listener. Called by the WebSocket layer to stream UI updates."""
        self._listeners.append(callback)

    async def _emit(self, event: ChangeEvent) -> None:
        for cb in self._listeners:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(event)
                else:
                    cb(event)
            except Exception as e:
                logger.warning(f"Change listener error: {e}")

    # Session
    @abstractmethod
    async def create_session(self, meta: SessionMeta) -> None: ...

    @abstractmethod
    async def get_session(self, session_id: str) -> Optional[SessionMeta]: ...

    @abstractmethod
    async def update_session(self, session_id: str, **kwargs) -> None: ...

    # Repo map
    @abstractmethod
    async def set_repo_map(self, session_id: str, repo_map: RepoMap) -> None: ...

    @abstractmethod
    async def get_repo_map(self, session_id: str) -> Optional[RepoMap]: ...

    # Agent states
    @abstractmethod
    async def upsert_agent_state(self, session_id: str, state: AgentState) -> None: ...

    @abstractmethod
    async def get_agent_state(self, session_id: str, agent_id: str) -> Optional[AgentState]: ...

    @abstractmethod
    async def get_all_agent_states(self, session_id: str) -> list[AgentState]: ...

    # Findings
    @abstractmethod
    async def add_finding(self, session_id: str, finding: Finding) -> None: ...

    @abstractmethod
    async def get_findings(self, session_id: str) -> list[Finding]: ...

    # HITL queue
    @abstractmethod
    async def push_question(self, session_id: str, question: HITLQuestion) -> None: ...

    @abstractmethod
    async def answer_question(self, session_id: str, question_id: str, answer: str) -> None: ...

    @abstractmethod
    async def get_pending_questions(self, session_id: str) -> list[HITLQuestion]: ...

    @abstractmethod
    async def get_question(self, session_id: str, question_id: str) -> Optional[HITLQuestion]: ...

    # Tool results
    @abstractmethod
    async def log_tool_result(self, session_id: str, result: ToolResult) -> None: ...

    @abstractmethod
    async def get_tool_results(self, session_id: str, agent_id: Optional[str] = None) -> list[ToolResult]: ...

    # Snapshot — used by report agent
    @abstractmethod
    async def snapshot(self, session_id: str) -> dict: ...


# ─── Local (in-process) Implementation ────────────────────────────────────────

class LocalMemoryStore(MemoryStore):
    """
    Pure in-process store using nested dicts.
    No external dependencies — use for local dev and all tests.
    Swap for CosmosMemoryStore by setting MEMORY_BACKEND=cosmos.
    Thread/async-safe via asyncio.Lock per session.
    """

    def __init__(self):
        super().__init__()
        # Structure: _data[session_id][namespace][key] = value
        self._data: dict[str, dict] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _session(self, session_id: str) -> dict:
        if session_id not in self._data:
            self._data[session_id] = {
                "session": None,
                "repo_map": None,
                "agent_states": {},   # agent_id → AgentState
                "findings": {},       # finding_id → Finding
                "hitl": {},           # question_id → HITLQuestion
                "tool_results": [],   # list[ToolResult]
            }
            self._locks[session_id] = asyncio.Lock()
        return self._data[session_id]

    def _lock(self, session_id: str) -> asyncio.Lock:
        self._session(session_id)   # ensure lock exists
        return self._locks[session_id]

    # ── Session ──────────────────────────────────────────────────────────────

    async def create_session(self, meta: SessionMeta) -> None:
        async with self._lock(meta.session_id):
            self._session(meta.session_id)["session"] = meta
        await self._emit(ChangeEvent("session", meta.session_id, meta.to_dict()))

    async def get_session(self, session_id: str) -> Optional[SessionMeta]:
        return self._session(session_id).get("session")

    async def update_session(self, session_id: str, **kwargs) -> None:
        async with self._lock(session_id):
            sess: SessionMeta = self._session(session_id)["session"]
            if not sess:
                raise KeyError(f"Session {session_id} not found")
            for k, v in kwargs.items():
                if hasattr(sess, k):
                    setattr(sess, k, v)
            sess.updated_at = _now()
        await self._emit(ChangeEvent("session", session_id, sess.to_dict()))

    # ── Repo map ─────────────────────────────────────────────────────────────

    async def set_repo_map(self, session_id: str, repo_map: RepoMap) -> None:
        async with self._lock(session_id):
            self._session(session_id)["repo_map"] = repo_map
        await self._emit(ChangeEvent("repo_map", session_id, repo_map.to_dict()))

    async def get_repo_map(self, session_id: str) -> Optional[RepoMap]:
        return self._session(session_id).get("repo_map")

    # ── Agent states ──────────────────────────────────────────────────────────

    async def upsert_agent_state(self, session_id: str, state: AgentState) -> None:
        async with self._lock(session_id):
            self._session(session_id)["agent_states"][state.agent_id] = state
        await self._emit(ChangeEvent("agent_state", state.agent_id, state.to_dict()))

    async def get_agent_state(self, session_id: str, agent_id: str) -> Optional[AgentState]:
        return self._session(session_id)["agent_states"].get(agent_id)

    async def get_all_agent_states(self, session_id: str) -> list[AgentState]:
        return list(self._session(session_id)["agent_states"].values())

    # ── Findings ──────────────────────────────────────────────────────────────

    async def add_finding(self, session_id: str, finding: Finding) -> None:
        async with self._lock(session_id):
            self._session(session_id)["findings"][finding.finding_id] = finding
        logger.info(f"[{session_id}] Finding {finding.finding_id}: {finding.severity.value} — {finding.title}")
        await self._emit(ChangeEvent("finding", finding.finding_id, finding.to_dict()))

    async def get_findings(self, session_id: str) -> list[Finding]:
        return list(self._session(session_id)["findings"].values())

    # ── HITL queue ────────────────────────────────────────────────────────────

    async def push_question(self, session_id: str, question: HITLQuestion) -> None:
        async with self._lock(session_id):
            self._session(session_id)["hitl"][question.question_id] = question
        logger.info(f"[{session_id}] HITL question {question.question_id} from {question.agent_id}")
        await self._emit(ChangeEvent("hitl_question", question.question_id, question.to_dict()))

    async def answer_question(self, session_id: str, question_id: str, answer: str) -> None:
        async with self._lock(session_id):
            q: HITLQuestion = self._session(session_id)["hitl"].get(question_id)
            if not q:
                raise KeyError(f"Question {question_id} not found")
            q.answer_question(answer)
        await self._emit(ChangeEvent("hitl_answer", question_id, q.to_dict()))

    async def get_pending_questions(self, session_id: str) -> list[HITLQuestion]:
        return [
            q for q in self._session(session_id)["hitl"].values()
            if q.status == HITLStatus.PENDING
        ]

    async def get_question(self, session_id: str, question_id: str) -> Optional[HITLQuestion]:
        return self._session(session_id)["hitl"].get(question_id)

    # ── Tool results ──────────────────────────────────────────────────────────

    async def log_tool_result(self, session_id: str, result: ToolResult) -> None:
        async with self._lock(session_id):
            self._session(session_id)["tool_results"].append(result)
        await self._emit(ChangeEvent("tool_result", result.call_id, result.to_dict()))

    async def get_tool_results(
        self, session_id: str, agent_id: Optional[str] = None
    ) -> list[ToolResult]:
        results = self._session(session_id)["tool_results"]
        if agent_id:
            return [r for r in results if r.agent_id == agent_id]
        return list(results)

    # ── Snapshot ──────────────────────────────────────────────────────────────

    async def snapshot(self, session_id: str) -> dict:
        """Full dump of session state. Used by ReportAgent to build the final report."""
        sess = self._session(session_id)
        return {
            "session": sess["session"].to_dict() if sess["session"] else None,
            "repo_map": sess["repo_map"].to_dict() if sess["repo_map"] else None,
            "agent_states": {k: v.to_dict() for k, v in sess["agent_states"].items()},
            "findings": [f.to_dict() for f in sess["findings"].values()],
            "hitl": [q.to_dict() for q in sess["hitl"].values()],
            "tool_results": [r.to_dict() for r in sess["tool_results"]],
        }
