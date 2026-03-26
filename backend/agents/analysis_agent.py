"""
HoneySentinel-OS -- AnalysisAgent
Analyses files, uses Azure AI Search for context, and reasons over vulnerabilities.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from backend.agents.base_agent import BaseAgent, _truncate
from backend.memory import AgentState, Finding, Severity
from backend.tools import FileScannerTool, PatternDetectorTool, YamlParserTool, DependencyCheckerTool
from backend.tools.azure_search_tool import AzureSearchTool  # <--- NEW IMPORT

logger = logging.getLogger(__name__)

def _normalize(path: str) -> str:
    return path.replace("\\", "/")

class AnalysisAgent(BaseAgent):

    def __init__(self, session_id: str, repo_path: str):
        super().__init__(
            agent_id="analysis-001",
            agent_type="analysis",
            goal="Analyse files for vulnerabilities. Use semantic search if you lack context. Write confirmed findings to shared memory.",
            session_id=session_id,
        )
        self.repo_path  = repo_path
        self._scanner   = FileScannerTool()
        self._detector  = PatternDetectorTool()
        self._yaml_tool = YamlParserTool()
        self._dep_tool  = DependencyCheckerTool()
        self._search    = AzureSearchTool() # <--- AGENT NOW HAS AZURE SEARCH

        self._files_todo: list[str]       = []
        self._files_done: set[str]        = set()
        self._current_file: Optional[str] = None

    async def _observe(self, state: AgentState) -> str:
        repo_map = await self.memory.get_repo_map(self.session_id)
        if not repo_map:
            return "Waiting for RepoMap from ReconAgent."

        if not self._files_todo:
            self._files_todo = [_normalize(f.path) for f in repo_map.files if not f.is_binary]

        remaining = [f for f in self._files_todo if f not in self._files_done]
        if not remaining:
            return "All files analysed."

        return f"{len(remaining)} files remaining. Next is {remaining[0]}."

    async def _plan(self, state: AgentState, observation: str) -> dict:
        if "Waiting" in observation:
            return {"thought": "Waiting for RepoMap.", "action": "wait"}
        if "All files" in observation:
            return {"thought": "Goal complete.", "action": "stop"}

        remaining = [f for f in self._files_todo if f not in self._files_done]
        next_file = remaining[0]
        self._current_file = next_file
        ext = next_file.rsplit(".", 1)[-1].lower() if "." in next_file else ""

        if ext in ("yaml", "yml", "json", "toml", "ini", "cfg", "env"):
            action = "parse_config"
        elif "requirements" in next_file and next_file.endswith(".txt"):
            action = "check_dependencies_py"
        else:
            action = "scan_patterns"

        return {
            "thought": f"Analysing {next_file} using {action}.",
            "action": action,
            "action_input": {"file_path": next_file},
        }

    async def _act(self, state: AgentState, plan: dict) -> Any:
        action = plan.get("action", "stop")
        if action in ("stop", "wait"): return {"status": action}

        file_path = _normalize(plan.get("action_input", {}).get("file_path", self._current_file))
        
        # --- AGENT USES AZURE SEARCH HERE IF NEEDED ---
        if action == "semantic_search":
            query = plan.get("action_input", {}).get("query", "")
            return self._search.search_codebase(query)

        repo_map  = await self.memory.get_repo_map(self.session_id)
        read_root = repo_map.root_path if repo_map else self.repo_path
        fc        = self._scanner.read_file_content(read_root, file_path)

        if "error" in fc:
            self._files_done.add(file_path)
            return {"error": fc["error"], "file": file_path}

        content  = fc.get("content", "")
        language = _ext_to_lang(file_path)

        if action == "parse_config":
            result = self._yaml_tool.parse_file(file_path, content)
        elif action == "check_dependencies_py":
            result = self._dep_tool.check_requirements_txt(content, file_path, read_root)
        else:
            scan = self._detector.scan_content(file_path, content, language)
            result = scan.to_dict()
            result["formatted"] = self._detector.format_matches_for_prompt(scan)

        self._files_done.add(file_path)
        return result

    async def _evaluate(self, state: AgentState, plan: dict, result: Any) -> dict:
        action = plan.get("action", "")
        if action in ("stop", "wait"):
            return {"confidence": 1.0, "goal_met": action == "stop", "reason": action}

        # Auto-handle tool failures smoothly without asking the human
        if isinstance(result, dict) and result.get("error"):
            return {"confidence": 1.0, "goal_met": False, "reason": f"Skipped due to error: {result['error']}"}

        file_path = plan.get("action_input", {}).get("file_path", "?")
        has_findings = result.get("match_count", 0) > 0 or result.get("flag_count", 0) > 0

        if not has_findings:
            return {"confidence": 1.0, "goal_met": False, "reason": f"No issues in {file_path}."}

        system_prompt = (
            "You are a Senior Security Analyst. Analyze the tool evidence. "
            "If you are unsure if this is a real vulnerability, set confidence below 0.95 and write a `human_question`. "
            "CRITICAL RULES FOR HUMAN QUESTION: "
            "1. It MUST be in simple, plain English for a non-technical product manager. "
            "2. NEVER include JSON, code, or raw file paths in the question. "
            "3. Provide 2 clear 'human_options' (e.g., ['Yes, this is just a test file', 'No, this is real data'])."
        )

        user_prompt = (
            f"FILE: {file_path}\nEVIDENCE:\n{json.dumps(result)[:2000]}\n\n"
            "RESPOND EXACTLY IN THIS JSON FORMAT:\n"
            "{\n"
            '  "findings": [{"rule_id": "HARDCODED_SECRET", "severity": "high", "title": "...", "description": "...", "evidence": "...", "recommendation": "...", "cwe_id": "...", "owasp": "..."}],\n'
            '  "overall_confidence": 0.85,\n'
            '  "human_question": "I noticed a password in this file. Is it used in production?",\n'
            '  "human_options": ["Just for testing", "Used in production"],\n'
            '  "suspicious_code_snippet": "exact 2-3 lines of code from the evidence that you want the human to look at"\n'
            "}"
        )

        raw = await self._llm_call(system_prompt, user_prompt)
        ev = _parse_json_safe(raw, {"findings": [], "overall_confidence": 1.0})

        for fd in ev.get("findings", []):
            await self.memory.add_finding(self.session_id, Finding(
                agent_id=self.agent_id,
                file_path=file_path,
                rule_id=fd.get("rule_id", "UNKNOWN"),
                severity=_parse_severity(fd.get("severity", "medium")),
                title=fd.get("title", "Security Issue"),
                description=fd.get("description", ""),
                evidence=fd.get("evidence", "")[:500],
                recommendation=fd.get("recommendation", ""),
                confidence=float(ev.get("overall_confidence", 0.9)),
                cwe_id=fd.get("cwe_id", ""),  # <--- RESTORED CWE
                owasp=fd.get("owasp", "")     # <--- RESTORED OWASP
            ))

        overall_conf = float(ev.get("overall_confidence", 1.0))
        hq = ev.get("human_question", "")
        if overall_conf < 0.95 and not hq:
            hq = "I found something suspicious here, but I need your business context. Should I flag this as a security risk?"
            ev["human_options"] = ["Yes, flag it", "No, ignore it"]

        return {
            "confidence": overall_conf,
            "goal_met": False,
            "reason": f"Analysed {file_path}.",
            "human_question": hq,
            "human_options": ev.get("human_options", []),
            "context": ev.get("suspicious_code_snippet", "") # <--- PASS SNIPPET TO HITL
        }

    async def _should_stop(self, state: AgentState, evaluation: dict) -> bool:
        if evaluation.get("goal_met"): return True
        return len([f for f in self._files_todo if f not in self._files_done]) == 0


def _ext_to_lang(file_path: str) -> str:
    return "python" if file_path.endswith(".py") else "unknown"

def _parse_severity(raw: str) -> Severity:
    m = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
    return m.get(raw.lower(), Severity.MEDIUM)

def _parse_json_safe(raw: str, default: dict) -> dict:
    try:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"): clean = clean[4:]
        return json.loads(clean)
    except:
        return default