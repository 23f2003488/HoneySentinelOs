"""
HoneySentinel-OS — OrchestratorAgent
Coordinates ReconAgent → AnalysisAgent → ReportAgent.
Monitors shared memory to know when each agent finishes.
Does NOT do security reasoning — that belongs to the sub-agents.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from backend.memory import (
    get_memory_store, SessionMeta, SessionStatus, AgentState,
    AgentStatus, _now,
)
from backend.policy import get_policy_engine
from backend.agents.recon_agent import ReconAgent
from backend.agents.analysis_agent import AnalysisAgent
from backend.agents.report_agent import ReportAgent

logger = logging.getLogger(__name__)


class OrchestratorAgent:
    """
    Top-level coordinator. Not a BaseAgent subclass because it does not
    run its own reasoning loop — it manages the loops of other agents.

    Workflow:
        1. Create session in memory
        2. Run ReconAgent (blocking — analysis needs the RepoMap)
        3. Run AnalysisAgent (blocking — report needs findings)
        4. Run ReportAgent
        5. Mark session done
    """

    def __init__(self, session_id: str, repo_path: str):
        self.session_id = session_id
        self.repo_path  = str(Path(repo_path).resolve())
        self.memory     = get_memory_store()
        self.policy     = get_policy_engine()
        self._report: dict = {}

    async def run(self) -> dict:
        """
        Full analysis pipeline. Returns the final report dict.
        This is what the FastAPI endpoint calls.
        """
        await self._init_session()

        try:
            # ── Phase 1: Recon ────────────────────────────────────────────────
            logger.info(f"[orchestrator] Starting ReconAgent for session {self.session_id}")
            await self._update_session(status=SessionStatus.RUNNING)

            recon = ReconAgent(self.session_id, self.repo_path)
            await recon.run()

            repo_map = await self.memory.get_repo_map(self.session_id)
            if not repo_map:
                raise RuntimeError("ReconAgent did not produce a RepoMap")

            logger.info(f"[orchestrator] ReconAgent done — {repo_map.total_files} files mapped")

            # ── Phase 2: Analysis ─────────────────────────────────────────────
            logger.info(f"[orchestrator] Starting AnalysisAgent")

            analysis = AnalysisAgent(self.session_id, self.repo_path)
            await analysis.run()

            findings = await self.memory.get_findings(self.session_id)
            logger.info(f"[orchestrator] AnalysisAgent done — {len(findings)} findings")

            # ── Phase 3: Report ───────────────────────────────────────────────
            logger.info(f"[orchestrator] Starting ReportAgent")

            reporter = ReportAgent(self.session_id)
            await reporter.run()

            self._report = reporter.get_report()
            logger.info(f"[orchestrator] ReportAgent done")

            orch_state = await self.memory.get_agent_state(self.session_id, "orchestrator")
            if orch_state:
                orch_state.update(status=AgentStatus.DONE, thought="All agents completed successfully.", decision="stop", finished_at=_now())
                await self.memory.upsert_agent_state(self.session_id, orch_state)

            await self._update_session(
                status      = SessionStatus.DONE,
                finished_at = _now(),
            )

            return self._report

        except Exception as e:
            logger.exception(f"[orchestrator] Pipeline failed")
            await self._update_session(
                status = SessionStatus.FAILED,
                error  = str(e),
            )
            raise

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _init_session(self) -> None:
        meta = SessionMeta(
            session_id    = self.session_id,
            status        = SessionStatus.INITIALIZING,
            input_source  = self.repo_path,
            input_type    = "git_repo",
            policy_version= self.policy.version,
            started_at    = _now(),
        )
        await self.memory.create_session(meta)

        # Register orchestrator itself in agent_states so UI can show it
        orch_state = AgentState(
            agent_id   = "orchestrator",
            agent_type = "orchestrator",
            goal       = f"Coordinate full analysis of {self.repo_path}",
            status     = AgentStatus.RUNNING,
            started_at = _now(),
        )
        await self.memory.upsert_agent_state(self.session_id, orch_state)

    async def _update_session(self, **kwargs) -> None:
        await self.memory.update_session(self.session_id, **kwargs)

    def get_report(self) -> dict:
        return self._report
