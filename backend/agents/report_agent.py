"""
HoneySentinel-OS — ReportAgent
Goal: read all findings from memory, synthesise a structured security report.
Runs after AnalysisAgent completes.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.agents.recon_agent import _parse_json_safe
from backend.memory import AgentState, Severity

logger = logging.getLogger(__name__)


class ReportAgent(BaseAgent):

    def __init__(self, session_id: str):
        super().__init__(
            agent_id   = "report-001",
            agent_type = "report",
            goal       = "Synthesise all findings from shared memory into a structured, actionable security report.",
            session_id = session_id,
        )
        self._report: dict = {}
        self._report_written = False

    # ── Observe ───────────────────────────────────────────────────────────────

    async def _observe(self, state: AgentState) -> str:
        findings = await self.memory.get_findings(self.session_id)
        repo_map = await self.memory.get_repo_map(self.session_id)
        snap     = await self.memory.snapshot(self.session_id)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        return (
            f"Total findings: {len(findings)}. "
            f"Breakdown: {counts}. "
            f"Repo: {repo_map.total_files if repo_map else 'unknown'} files scanned. "
            f"Report written: {self._report_written}."
        )

    # ── Plan ──────────────────────────────────────────────────────────────────

    async def _plan(self, state: AgentState, observation: str) -> dict:
        if self._report_written:
            return {"thought": "Report already written.", "action": "stop", "action_input": {}}

        return {
            "thought": "Generate the structured security report from all findings in memory.",
            "action": "generate_report",
            "action_input": {},
        }

    # ── Act ───────────────────────────────────────────────────────────────────

    async def _act(self, state: AgentState, plan: dict) -> Any:
        if plan.get("action") == "stop":
            return {"status": "done"}

        findings  = await self.memory.get_findings(self.session_id)
        repo_map  = await self.memory.get_repo_map(self.session_id)
        snap      = await self.memory.snapshot(self.session_id)

        # Build finding summaries for the prompt
        finding_summaries = []
        for f in findings:
            action = self.policy.get_severity_action(f.severity.value)
            finding_summaries.append({
                "id":             f.finding_id,
                "rule":           f.rule_id,
                "severity":       f.severity.value,
                "title":          f.title,
                "file":           f.file_path,
                "description":    f.description[:300],
                "evidence":       f.evidence[:200],
                "recommendation": f.recommendation[:200],
                "confidence":     f.confidence,
                "action":         action.recommended_action if action else "Review",
                "escalate":       action.escalate if action else False,
            })

        prompt = f"""{self._base_system_prompt()}

You are generating the final security report. Here is all available data:

PROJECT: {self.policy.context.project_name}
FILES SCANNED: {repo_map.total_files if repo_map else 'unknown'}
TOTAL FINDINGS: {len(findings)}

FINDINGS:
{json.dumps(finding_summaries, indent=2)[:4000]}

Generate a structured security report. Respond ONLY with valid JSON:
{{
  "executive_summary": "2-3 sentences for non-technical stakeholders",
  "risk_rating": "critical|high|medium|low",
  "critical_findings": ["finding_id list"],
  "high_findings": ["finding_id list"],
  "medium_findings": ["finding_id list"],
  "low_findings": ["finding_id list"],
  "top_recommendations": [
    {{"priority": 1, "action": "...", "rationale": "..."}}
  ],
  "files_with_most_issues": ["file paths"],
  "most_common_weakness": "rule_id",
  "remediation_effort": "low|medium|high",
  "conclusion": "One paragraph conclusion"
}}"""

        raw = await self._llm_call(
            system_prompt = "You are a security report agent. Output only valid JSON.",
            user_prompt   = prompt,
            max_tokens    = 2000,
            temperature   = 0.2,
        )

        report_data = _parse_json_safe(raw, default={
            "executive_summary": f"Analysis complete. {len(findings)} findings identified.",
            "risk_rating": "medium",
            "top_recommendations": [],
        })

        # Attach raw findings for UI
        report_data["findings"]     = finding_summaries
        report_data["total_files"]  = repo_map.total_files if repo_map else 0
        report_data["session_id"]   = self.session_id
        report_data["policy_version"] = self.policy.version

        self._report = report_data
        self._report_written = True

        # Persist to memory as a special tool result
        await self._log_tool(
            tool_name     = "report_agent.generate_report",
            input_summary = f"{len(findings)} findings",
            output        = report_data,
            duration_ms   = 0,
        )

        return {"status": "report_generated", "report": report_data}

    # ── Evaluate ──────────────────────────────────────────────────────────────

    async def _evaluate(self, state: AgentState, plan: dict, result: Any) -> dict:
        if isinstance(result, dict) and result.get("status") in ("done", "report_generated"):
            return {"confidence": 1.0, "goal_met": True, "reason": "Report complete."}
        return {"confidence": 0.5, "goal_met": False, "reason": "Retrying report generation."}

    async def _should_stop(self, state: AgentState, evaluation: dict) -> bool:
        return evaluation.get("goal_met", False)

    def get_report(self) -> dict:
        return self._report
