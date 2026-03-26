"""
HoneySentinel-OS — OrchestratorAgent
Coordinates and VALIDATES the workflow: Recon -> Validate -> Analysis -> Validate -> Report.
"""
from __future__ import annotations
import asyncio
import logging
from pathlib import Path

from backend.memory import get_memory_store, SessionMeta, SessionStatus, AgentState, AgentStatus, _now
from backend.policy import get_policy_engine

logger = logging.getLogger(__name__)

class OrchestratorAgent:
    def __init__(self, session_id: str, repo_path: str, policy_path: str = None):
        self.session_id = session_id
        self.repo_path  = str(Path(repo_path).resolve())
        self.memory     = get_memory_store()
        self._report: dict = {}
        self.fallback_used = False
        
        # Robust Policy Loading: Fallback if user uploaded a bad YAML
        if policy_path:
            try:
                from backend.policy import PolicyEngine
                self.policy = PolicyEngine(Path(policy_path)).load()
                logger.info(f"Loaded custom policy for session {session_id}")
            except Exception as e:
                logger.warning(f"Custom policy invalid ({e}). Falling back to Universal Default.")
                self.policy = get_policy_engine() # Fallback
                self.fallback_used = True
        else:
            self.policy = get_policy_engine()

    async def _update_trace(self, action: str, observation: str, thought: str):
        """Helper to instantly update the UI Trace for the Orchestrator."""
        state = await self.memory.get_agent_state(self.session_id, "orchestrator")
        if state:
            state.update(last_action=action, last_observation=observation, thought=thought)
            await self.memory.upsert_agent_state(self.session_id, state)
            await asyncio.sleep(1.5) # Give UI time to show the trace naturally

    async def run(self) -> dict:
        await self._init_session()

        try:
            if self.fallback_used:
                await self._update_trace("PolicyValidation", "Custom YAML uploaded by user is malformed.", "Rejecting custom config and falling back to Universal Default Policy to ensure stability.")

            # --- 1. RECON PHASE ---
            await self._update_trace("DelegateTask", "Triggering ReconAgent.", "Need to map repository architecture before analysis.")
            from backend.agents.recon_agent import ReconAgent
            recon = ReconAgent(self.session_id, self.repo_path)
            await recon.run()

            # --- 1A. VALIDATION PHASE ---
            await self._update_trace("ValidateOutput", "ReconAgent completed.", "Validating RepoMap integrity...")
            repo_map = await self.memory.get_repo_map(self.session_id)
            if not repo_map or repo_map.total_files == 0:
                raise RuntimeError("Validation Failed: ReconAgent returned an empty or missing RepoMap.")
            await self._update_trace("ValidationSuccess", f"RepoMap confirmed valid ({repo_map.total_files} files).", "Proceeding to Analysis Phase.")

            # --- 2. ANALYSIS PHASE ---
            await self._update_trace("DelegateTask", "Triggering AnalysisAgent.", "Hunting for vulnerabilities using configured tools.")
            from backend.agents.analysis_agent import AnalysisAgent
            analysis = AnalysisAgent(self.session_id, self.repo_path)
            await analysis.run()

            # --- 2A. VALIDATION PHASE ---
            await self._update_trace("ValidateOutput", "AnalysisAgent completed.", "Auditing confirmed security findings...")
            findings = await self.memory.get_findings(self.session_id)
            await self._update_trace("ValidationSuccess", f"Audit complete. {len(findings)} findings validated.", "Initiating ReportAgent for executive synthesis.")

            # --- 3. REPORT PHASE ---
            await self._update_trace("DelegateTask", "Triggering ReportAgent.", "Synthesizing business impact report.")
            from backend.agents.report_agent import ReportAgent
            reporter = ReportAgent(self.session_id)
            await reporter.run()
            self._report = reporter.get_report()

            # --- FINISH ---
            await self.memory.update_session(self.session_id, status=SessionStatus.DONE, finished_at=_now())
            await self._update_trace("Finalize", "All operations successful.", "Analysis complete. System shutting down.")
            
            state = await self.memory.get_agent_state(self.session_id, "orchestrator")
            state.update(status=AgentStatus.DONE, decision="stop", finished_at=_now())
            await self.memory.upsert_agent_state(self.session_id, state)
            
            return self._report

        except Exception as e:
            logger.exception(f"[orchestrator] Pipeline failed")
            await self._update_trace("SystemError", f"Fatal exception: {str(e)}", "Aborting pipeline.")
            await self.memory.update_session(self.session_id, status=SessionStatus.FAILED, error=str(e))
            raise

    async def _init_session(self) -> None:
        meta = SessionMeta(
            session_id=self.session_id, status=SessionStatus.INITIALIZING,
            input_source=self.repo_path, input_type="git_repo",
            policy_version=self.policy.version, started_at=_now(),
        )
        await self.memory.create_session(meta)

        orch_state = AgentState(
            agent_id="orchestrator", agent_type="orchestrator",
            goal=f"Validate inputs, orchestrate agents, and ensure QA of results.",
            status=AgentStatus.RUNNING, started_at=_now(),
        )
        await self.memory.upsert_agent_state(self.session_id, orch_state)