"""
HoneySentinel-OS — OrchestratorAgent
Coordinates and VALIDATES the workflow.
"""
from __future__ import annotations
import asyncio
import logging
from pathlib import Path
from backend.memory import get_memory_store, SessionMeta, SessionStatus, AgentState, AgentStatus, _now
from backend.policy import get_policy_engine, PolicyEngine, PolicyLoadError

logger = logging.getLogger(__name__)

class OrchestratorAgent:
    def __init__(self, session_id: str, repo_path: str, policy_path: str = None):
        self.session_id = session_id
        self.repo_path  = str(Path(repo_path).resolve())
        self.memory     = get_memory_store()
        self.policy_path = policy_path 
        self.policy = None 

    async def _update_trace(self, action: str, observation: str, thought: str):
        state = await self.memory.get_agent_state(self.session_id, "orchestrator")
        if state:
            state.update(last_action=action, last_observation=observation, thought=thought)
            await self.memory.upsert_agent_state(self.session_id, state)
            await asyncio.sleep(1.0)

    async def run(self) -> dict:
        # Load policy here, safely
        from backend.policy import PolicyEngine
        fallback = False
        fallback_msg = ""
        
        try:
            if self.policy_path:
                self.policy = PolicyEngine(Path(self.policy_path)).load()
            else:
                self.policy = get_policy_engine()
        except Exception as e:
            fallback = True
            fallback_msg = str(e)
            self.policy = get_policy_engine()

        await self._init_session()
        
        if fallback:
            await self._update_trace("PolicyValidation", f"Custom YAML invalid: {fallback_msg}", "Falling back to Universal Default.")

        # --- RECON ---
        try:
            await self._update_trace("DelegateTask", "Triggering ReconAgent.", "Mapping repository...")
            from backend.agents.recon_agent import ReconAgent
            recon = ReconAgent(self.session_id, self.repo_path)
            await recon.run()

            # --- 1A. VALIDATION ---
            repo_map = await self.memory.get_repo_map(self.session_id)
            if not repo_map or repo_map.total_files == 0:
                raise RuntimeError("Validation Failed: ReconAgent produced no files.")
            await self._update_trace("ValidationSuccess", "RepoMap verified.", "Proceeding to Analysis.")

            # --- 2. ANALYSIS PHASE ---
            from backend.agents.analysis_agent import AnalysisAgent
            analysis = AnalysisAgent(self.session_id, self.repo_path)
            await analysis.run()

            # --- 3. REPORT PHASE ---
            from backend.agents.report_agent import ReportAgent
            reporter = ReportAgent(self.session_id)
            await reporter.run()
            self._report = reporter.get_report()

            # --- FINISH ---
            await self.memory.update_session(self.session_id, status=SessionStatus.DONE, finished_at=_now())
            state = await self.memory.get_agent_state(self.session_id, "orchestrator")
            state.update(status=AgentStatus.DONE, decision="stop", finished_at=_now())
            await self.memory.upsert_agent_state(self.session_id, state)
            return self._report

        except Exception as e:
            logger.exception(f"[orchestrator] Pipeline failed")
            await self._update_trace("SystemError", str(e), "Pipeline Aborted.")
            await self.memory.update_session(self.session_id, status=SessionStatus.FAILED, error=str(e))
            raise

    async def _init_session(self) -> None:
        # ... (Keep _init_session exactly as you had it) ...
        meta = SessionMeta(session_id=self.session_id, status=SessionStatus.INITIALIZING, input_source=self.repo_path, input_type="git_repo", policy_version=self.policy.version, started_at=_now())
        await self.memory.create_session(meta)
        orch_state = AgentState(agent_id="orchestrator", agent_type="orchestrator", goal=f"Coordinate full analysis of {self.repo_path}", status=AgentStatus.RUNNING, started_at=_now())
        await self.memory.upsert_agent_state(self.session_id, orch_state)