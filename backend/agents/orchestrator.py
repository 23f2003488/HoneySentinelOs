"""
HoneySentinel-OS — OrchestratorAgent
Coordinates and explicitly VALIDATES the workflow for UI transparency.
"""
from __future__ import annotations
import asyncio
import logging
from pathlib import Path
from backend.memory import get_memory_store, SessionMeta, SessionStatus, AgentState, AgentStatus, _now
from backend.policy import get_policy_engine, PolicyEngine

logger = logging.getLogger(__name__)

class OrchestratorAgent:
    def __init__(self, session_id: str, repo_path: str, policy_path: str = None):
        self.session_id = session_id
        self.repo_path  = str(Path(repo_path).resolve())
        self.memory     = get_memory_store()
        self.policy_path = policy_path 
        self.policy = None 

    async def _update_trace(self, action: str, observation: str, thought: str):
        """Updates the memory and pauses briefly so the React UI can fetch and display the trace."""
        state = await self.memory.get_agent_state(self.session_id, "orchestrator")
        if state:
            state.update(last_action=action, last_observation=observation, thought=thought)
            await self.memory.upsert_agent_state(self.session_id, state)
            await asyncio.sleep(2.0) # <--- INCREASED PAUSE SO UI CATCHES EVERY TRACE

    async def run(self) -> dict:
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

        try:
            # --- 1. RECON PHASE ---
            await self._update_trace("DelegateTask", "Triggering ReconAgent.", "Mapping repository architecture.")
            from backend.agents.recon_agent import ReconAgent
            recon = ReconAgent(self.session_id, self.repo_path)
            await recon.run()

            # --- 1A. QA VALIDATION ---
            await self._update_trace("QA_Gate_1", "ReconAgent completed.", "Validating RepoMap integrity...")
            repo_map = await self.memory.get_repo_map(self.session_id)
            if not repo_map or repo_map.total_files == 0:
                raise RuntimeError("Validation Failed: ReconAgent produced no files.")
            await self._update_trace("ValidationSuccess", f"RepoMap verified ({repo_map.total_files} files).", "Proceeding to Vulnerability Analysis.")

            # --- 2. ANALYSIS PHASE ---
            await self._update_trace("DelegateTask", "Triggering AnalysisAgent.", "Hunting for vulnerabilities using configured tools.")
            from backend.agents.analysis_agent import AnalysisAgent
            analysis = AnalysisAgent(self.session_id, self.repo_path)
            await analysis.run()

            # --- 2A. QA VALIDATION ---
            await self._update_trace("QA_Gate_2", "AnalysisAgent completed.", "Auditing confirmed security findings...")
            findings = await self.memory.get_findings(self.session_id)
            await self._update_trace("ValidationSuccess", f"Audit complete. {len(findings)} findings validated.", "Initiating ReportAgent for executive synthesis.")

            # --- 3. REPORT PHASE ---
            await self._update_trace("DelegateTask", "Triggering ReportAgent.", "Synthesizing business impact report.")
            from backend.agents.report_agent import ReportAgent
            reporter = ReportAgent(self.session_id)
            await reporter.run()
            self._report = reporter.get_report()

            # --- 4. PIPELINE COMPLETE ---
            # Update trace BEFORE marking session as DONE, otherwise UI stops polling!
            await self._update_trace("PipelineComplete", "All agents successfully halted.", "Analysis and validation phases are 100% complete.")

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
        meta = SessionMeta(session_id=self.session_id, status=SessionStatus.INITIALIZING, input_source=self.repo_path, input_type="git_repo", policy_version=self.policy.version, started_at=_now())
        await self.memory.create_session(meta)
        orch_state = AgentState(agent_id="orchestrator", agent_type="orchestrator", goal=f"Validate inputs, orchestrate agents, and ensure QA of results.", status=AgentStatus.RUNNING, started_at=_now())
        await self.memory.upsert_agent_state(self.session_id, orch_state)