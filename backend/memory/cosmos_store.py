"""
HoneySentinel-OS — CosmosMemoryStore
Azure Cosmos DB backend for shared memory.

This stub prevents import crashes when MEMORY_BACKEND=cosmos is set
but Cosmos has not been provisioned yet.

To activate:
1. Provision Azure Cosmos DB (NoSQL API, serverless)
2. Add to .env:
     MEMORY_BACKEND=cosmos
     COSMOS_ENDPOINT=https://your-account.documents.azure.com:443/
     COSMOS_KEY=your-key
     COSMOS_DATABASE=honeySentinel
     COSMOS_CONTAINER=memory
3. The full implementation will replace this stub in Phase 4.
"""

from __future__ import annotations
import os
import logging
from typing import Optional

from .store import MemoryStore
from .models import (
    AgentState, Finding, HITLQuestion, HITLStatus,
    RepoMap, SessionMeta, ToolResult, _now,
)

logger = logging.getLogger(__name__)


class CosmosMemoryStore(MemoryStore):
    """
    Azure Cosmos DB implementation of MemoryStore.
    Currently a stub — falls back to raising NotImplementedError
    with a clear message telling you what to provision.
    Full implementation is added once Cosmos DB is set up.
    """

    def __init__(self):
        super().__init__()
        endpoint = os.getenv("COSMOS_ENDPOINT", "")
        key      = os.getenv("COSMOS_KEY", "")

        if not endpoint or not key:
            raise RuntimeError(
                "CosmosMemoryStore requires COSMOS_ENDPOINT and COSMOS_KEY in your .env file.\n"
                "Either provision Azure Cosmos DB and set those variables,\n"
                "or set MEMORY_BACKEND=local to use the local in-memory store."
            )

        # Placeholder — real client initialised once azure-cosmos is installed
        self._endpoint = endpoint
        self._key      = key
        self._database = os.getenv("COSMOS_DATABASE", "honeySentinel")
        self._container= os.getenv("COSMOS_CONTAINER", "memory")
        logger.info(f"CosmosMemoryStore stub initialised → {endpoint}")

    def _not_implemented(self, method: str):
        raise NotImplementedError(
            f"CosmosMemoryStore.{method} is not yet implemented. "
            "Set MEMORY_BACKEND=local to use LocalMemoryStore."
        )

    async def create_session(self, meta: SessionMeta) -> None:
        self._not_implemented("create_session")

    async def get_session(self, session_id: str) -> Optional[SessionMeta]:
        self._not_implemented("get_session")

    async def update_session(self, session_id: str, **kwargs) -> None:
        self._not_implemented("update_session")

    async def set_repo_map(self, session_id: str, repo_map: RepoMap) -> None:
        self._not_implemented("set_repo_map")

    async def get_repo_map(self, session_id: str) -> Optional[RepoMap]:
        self._not_implemented("get_repo_map")

    async def upsert_agent_state(self, session_id: str, state: AgentState) -> None:
        self._not_implemented("upsert_agent_state")

    async def get_agent_state(self, session_id: str, agent_id: str) -> Optional[AgentState]:
        self._not_implemented("get_agent_state")

    async def get_all_agent_states(self, session_id: str) -> list[AgentState]:
        self._not_implemented("get_all_agent_states")

    async def add_finding(self, session_id: str, finding: Finding) -> None:
        self._not_implemented("add_finding")

    async def get_findings(self, session_id: str) -> list[Finding]:
        self._not_implemented("get_findings")

    async def push_question(self, session_id: str, question: HITLQuestion) -> None:
        self._not_implemented("push_question")

    async def answer_question(self, session_id: str, question_id: str, answer: str) -> None:
        self._not_implemented("answer_question")

    async def get_pending_questions(self, session_id: str) -> list[HITLQuestion]:
        self._not_implemented("get_pending_questions")

    async def get_question(self, session_id: str, question_id: str) -> Optional[HITLQuestion]:
        self._not_implemented("get_question")

    async def log_tool_result(self, session_id: str, result: ToolResult) -> None:
        self._not_implemented("log_tool_result")

    async def get_tool_results(self, session_id: str, agent_id: Optional[str] = None) -> list[ToolResult]:
        self._not_implemented("get_tool_results")

    async def snapshot(self, session_id: str) -> dict:
        self._not_implemented("snapshot")
