"""
HoneySentinel-OS — CosmosMemoryStore
Azure Cosmos DB (NoSQL API) backend for shared memory.
Stores all session data, agent states, and findings in a single container,
partitioned by `session_id` for extremely fast, isolated retrieval.
"""

from __future__ import annotations
import os
import logging
from typing import Optional

from azure.cosmos.aio import CosmosClient
from azure.cosmos.exceptions import CosmosResourceNotFoundError

from .store import MemoryStore
from .models import (
    AgentState, AgentStatus, Finding, HITLQuestion, HITLStatus,
    RepoMap, SessionMeta, SessionStatus, ToolResult, Severity, _now,
)

logger = logging.getLogger(__name__)


class CosmosMemoryStore(MemoryStore):
    def __init__(self):
        super().__init__()
        endpoint = os.getenv("COSMOS_ENDPOINT", "")
        key      = os.getenv("COSMOS_KEY", "")

        if not endpoint or not key:
            raise RuntimeError(
                "CosmosMemoryStore requires COSMOS_ENDPOINT and COSMOS_KEY in your .env file."
            )

        self._endpoint = endpoint
        self._key = key
        self._database_name = os.getenv("COSMOS_DATABASE_NAME", "HoneySentinelDB")
        self._container_name = os.getenv("COSMOS_CONTAINER_NAME", "AgentMemory")
        
        # Initialize Async Cosmos Client
        self.client = CosmosClient(self._endpoint, credential=self._key)
        self.database = self.client.get_database_client(self._database_name)
        self.container = self.database.get_container_client(self._container_name)
        
        logger.info(f"CosmosMemoryStore initialized → {self._endpoint}")

    # ── Helpers ─────────────────────────────────────────────────────────────

    async def _upsert(self, doc_type: str, doc_id: str, session_id: str, data: dict) -> None:
        """Helper to inject required Cosmos DB fields and upsert."""
        data["id"] = f"{doc_type}_{doc_id}"
        data["session_id"] = session_id  # This is our Partition Key
        data["doc_type"] = doc_type
        await self.container.upsert_item(data)

    async def _query_type(self, session_id: str, doc_type: str) -> list[dict]:
        """Fetch all documents of a specific type for a session."""
        query = "SELECT * FROM c WHERE c.session_id = @sid AND c.doc_type = @type"
        parameters = [
            {"name": "@sid", "value": session_id},
            {"name": "@type", "value": doc_type}
        ]
        items = self.container.query_items(
            query=query, 
            parameters=parameters, 
            partition_key=session_id
        )
        return [item async for item in items]

    async def _get_item(self, session_id: str, doc_type: str, doc_id: str) -> Optional[dict]:
        """Fetch a single item by its ID."""
        item_id = f"{doc_type}_{doc_id}"
        try:
            return await self.container.read_item(item=item_id, partition_key=session_id)
        except CosmosResourceNotFoundError:
            return None

    # ── Session ──────────────────────────────────────────────────────────────

    async def create_session(self, meta: SessionMeta) -> None:
        await self._upsert("session", meta.session_id, meta.session_id, meta.to_dict())

    async def get_session(self, session_id: str) -> Optional[SessionMeta]:
        data = await self._get_item(session_id, "session", session_id)
        if data:
            return SessionMeta(**{k: v for k, v in data.items() if k in SessionMeta.__annotations__})
        return None

    async def update_session(self, session_id: str, **kwargs) -> None:
        data = await self._get_item(session_id, "session", session_id)
        if not data:
            raise KeyError(f"Session {session_id} not found")
        for k, v in kwargs.items():
            data[k] = v.value if isinstance(v, SessionStatus) else v
        data["updated_at"] = _now()
        await self.container.upsert_item(data)

    # ── Repo map ─────────────────────────────────────────────────────────────

    async def set_repo_map(self, session_id: str, repo_map: RepoMap) -> None:
        await self._upsert("repomap", session_id, session_id, repo_map.to_dict())

    async def get_repo_map(self, session_id: str) -> Optional[RepoMap]:
        data = await self._get_item(session_id, "repomap", session_id)
        if not data:
            return None
        # Exclude cosmos-specific keys before passing to model
        clean_data = {k: v for k, v in data.items() if k not in ["id", "session_id", "doc_type", "_rid", "_self", "_etag", "_attachments", "_ts"]}
        from .models import FileNode
        clean_data["files"] = [FileNode(**f) for f in clean_data.get("files", [])]
        return RepoMap(**clean_data)

    # ── Agent states ──────────────────────────────────────────────────────────

    async def upsert_agent_state(self, session_id: str, state: AgentState) -> None:
        await self._upsert("agentstate", state.agent_id, session_id, state.to_dict())

    async def get_agent_state(self, session_id: str, agent_id: str) -> Optional[AgentState]:
        data = await self._get_item(session_id, "agentstate", agent_id)
        if data:
            data["status"] = AgentStatus(data["status"])
            return AgentState(**{k: v for k, v in data.items() if k in AgentState.__annotations__})
        return None

    async def get_all_agent_states(self, session_id: str) -> list[AgentState]:
        items = await self._query_type(session_id, "agentstate")
        states = []
        for data in items:
            data["status"] = AgentStatus(data["status"])
            states.append(AgentState(**{k: v for k, v in data.items() if k in AgentState.__annotations__}))
        return states

    # ── Findings ──────────────────────────────────────────────────────────────

    async def add_finding(self, session_id: str, finding: Finding) -> None:
        await self._upsert("finding", finding.finding_id, session_id, finding.to_dict())
        logger.info(f"[{session_id}] Finding saved to Cosmos: {finding.rule_id}")

    async def get_findings(self, session_id: str) -> list[Finding]:
        items = await self._query_type(session_id, "finding")
        findings = []
        for data in items:
            data["severity"] = Severity(data["severity"])
            findings.append(Finding(**{k: v for k, v in data.items() if k in Finding.__annotations__}))
        return findings

    # ── HITL queue ────────────────────────────────────────────────────────────

    async def push_question(self, session_id: str, question: HITLQuestion) -> None:
        await self._upsert("hitl", question.question_id, session_id, question.to_dict())
        logger.info(f"[{session_id}] HITL pushed to Cosmos: {question.question_id}")

    async def answer_question(self, session_id: str, question_id: str, answer: str) -> None:
        data = await self._get_item(session_id, "hitl", question_id)
        if not data:
            raise KeyError(f"Question {question_id} not found")
        data["answer"] = answer
        data["status"] = HITLStatus.ANSWERED.value
        data["answered_at"] = _now()
        await self.container.upsert_item(data)

    async def get_pending_questions(self, session_id: str) -> list[HITLQuestion]:
        items = await self._query_type(session_id, "hitl")
        pending = []
        for data in items:
            if data.get("status") == HITLStatus.PENDING.value:
                data["status"] = HITLStatus(data["status"])
                pending.append(HITLQuestion(**{k: v for k, v in data.items() if k in HITLQuestion.__annotations__}))
        return pending

    async def get_question(self, session_id: str, question_id: str) -> Optional[HITLQuestion]:
        data = await self._get_item(session_id, "hitl", question_id)
        if data:
            data["status"] = HITLStatus(data["status"])
            return HITLQuestion(**{k: v for k, v in data.items() if k in HITLQuestion.__annotations__})
        return None

    # ── Tool results ──────────────────────────────────────────────────────────

    async def log_tool_result(self, session_id: str, result: ToolResult) -> None:
        await self._upsert("toolresult", result.call_id, session_id, result.to_dict())

    async def get_tool_results(self, session_id: str, agent_id: Optional[str] = None) -> list[ToolResult]:
        items = await self._query_type(session_id, "toolresult")
        results = []
        for data in items:
            if agent_id and data.get("agent_id") != agent_id:
                continue
            results.append(ToolResult(**{k: v for k, v in data.items() if k in ToolResult.__annotations__}))
        return results

    # ── Snapshot ──────────────────────────────────────────────────────────────

    async def snapshot(self, session_id: str) -> dict:
        """Fetch ALL data for a session_id in a single efficient Cosmos partition query."""
        query = "SELECT * FROM c WHERE c.session_id = @sid"
        items = self.container.query_items(
            query=query, 
            parameters=[{"name": "@sid", "value": session_id}], 
            partition_key=session_id
        )
        
        snap = {
            "session": None,
            "repo_map": None,
            "agent_states": {},
            "findings": [],
            "hitl": [],
            "tool_results": []
        }
        
        async for doc in items:
            dt = doc.get("doc_type")
            # Strip Cosmos DB metadata keys
            clean_doc = {k: v for k, v in doc.items() if not k.startswith('_') and k not in ['id', 'session_id', 'doc_type']}
            
            if dt == "session":
                snap["session"] = clean_doc
            elif dt == "repomap":
                snap["repo_map"] = clean_doc
            elif dt == "agentstate":
                snap["agent_states"][clean_doc.get("agent_id")] = clean_doc
            elif dt == "finding":
                snap["findings"].append(clean_doc)
            elif dt == "hitl":
                snap["hitl"].append(clean_doc)
            elif dt == "toolresult":
                snap["tool_results"].append(clean_doc)
                
        return snap