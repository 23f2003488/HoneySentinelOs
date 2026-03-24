"""
HoneySentinel-OS -- AnalysisAgent
Analyses every in-scope file using tools then reasons with Azure OpenAI to produce findings.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from backend.agents.base_agent import BaseAgent, _truncate
from backend.memory import AgentState, Finding, Severity
from backend.tools import FileScannerTool, PatternDetectorTool, YamlParserTool, DependencyCheckerTool

logger = logging.getLogger(__name__)

BACKSLASH = "\\"


def _normalize(path: str) -> str:
    return path.replace(BACKSLASH, "/")


class AnalysisAgent(BaseAgent):

    def __init__(self, session_id: str, repo_path: str):
        super().__init__(
            agent_id="analysis-001",
            agent_type="analysis",
            goal="Analyse every in-scope file for security vulnerabilities using tools and policy rules. Write confirmed findings to shared memory.",
            session_id=session_id,
        )
        self.repo_path  = repo_path
        self._scanner   = FileScannerTool()
        self._detector  = PatternDetectorTool()
        self._yaml_tool = YamlParserTool()
        self._dep_tool  = DependencyCheckerTool()

        self._files_todo: list[str]       = []
        self._files_done: set[str]        = set()
        self._current_file: Optional[str] = None

    # -- Observe ---------------------------------------------------------------

    async def _observe(self, state: AgentState) -> str:
        repo_map = await self.memory.get_repo_map(self.session_id)
        if not repo_map:
            return "RepoMap not in memory yet. Waiting for ReconAgent to complete."

        if not self._files_todo:
            self._files_todo = [_normalize(f.path) for f in repo_map.files if not f.is_binary]

        remaining = [f for f in self._files_todo if f not in self._files_done]
        findings  = await self.memory.get_findings(self.session_id)
        next_info = ("Next: " + remaining[0]) if remaining else "All files analysed."
        return (
            f"Repo has {len(self._files_todo)} in-scope files. "
            f"{len(self._files_done)} analysed, {len(remaining)} remaining. "
            f"{len(findings)} findings so far. {next_info}"
        )

    # -- Plan ------------------------------------------------------------------

    async def _plan(self, state: AgentState, observation: str) -> dict:
        if "Waiting for ReconAgent" in observation:
            return {"thought": "Waiting for RepoMap.", "action": "wait", "action_input": {}}

        if "All files analysed" in observation:
            return {"thought": "All files analysed. Goal complete.", "action": "stop", "action_input": {}}

        remaining = [f for f in self._files_todo if f not in self._files_done]
        if not remaining:
            return {"thought": "No files remaining.", "action": "stop", "action_input": {}}

        next_file = remaining[0]
        self._current_file = next_file
        ext = next_file.rsplit(".", 1)[-1].lower() if "." in next_file else ""

        if ext in ("yaml", "yml", "json", "toml", "ini", "cfg", "env"):
            action = "parse_config"
        elif "requirements" in next_file and next_file.endswith(".txt"):
            action = "check_dependencies_py"
        elif next_file.endswith("package.json"):
            action = "check_dependencies_js"
        else:
            action = "scan_patterns"

        return {
            "thought": f"Analysing {next_file} using {action}.",
            "action": action,
            "action_input": {"file_path": next_file},
        }

    # -- Act -------------------------------------------------------------------

    async def _act(self, state: AgentState, plan: dict) -> Any:
        action    = plan.get("action", "stop")
        file_path = plan.get("action_input", {}).get("file_path", self._current_file)

        if action in ("stop", "wait"):
            return {"status": action}

        if file_path:
            file_path = _normalize(file_path)

        start     = time.time()
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
            tool   = "yaml_parser"
        elif action == "check_dependencies_py":
            result = self._dep_tool.check_requirements_txt(content, file_path)
            tool   = "dep_checker_py"
        elif action == "check_dependencies_js":
            result = self._dep_tool.check_package_json(content, file_path)
            tool   = "dep_checker_js"
        else:
            scan   = self._detector.scan_content(file_path, content, language)
            result = scan.to_dict()
            result["formatted"]    = self._detector.format_matches_for_prompt(scan)
            result["file_content"] = content[:3000]
            tool   = "pattern_detector"

        duration = int((time.time() - start) * 1000)
        await self._log_tool(
            tool_name=tool, input_summary=f"file={file_path}",
            output={k: v for k, v in result.items() if k not in ("formatted", "file_content")},
            duration_ms=duration, success="error" not in result, error=result.get("error"),
        )
        self._files_done.add(file_path)
        return result

    # -- Evaluate --------------------------------------------------------------

    async def _evaluate(self, state: AgentState, plan: dict, result: Any) -> dict:
        action = plan.get("action", "")

        if action in ("stop", "wait"):
            return {"confidence": 1.0, "goal_met": action == "stop", "reason": action}

        if isinstance(result, dict) and "error" in result:
            return {"confidence": 0.9, "goal_met": False, "reason": f"Skipped: {result['error']}"}

        findings = await self.memory.get_findings(self.session_id)
        if len(findings) >= self._cfg.max_findings:
            return {"confidence": 1.0, "goal_met": True, "reason": "Max findings reached."}

        file_path   = plan.get("action_input", {}).get("file_path", "?")
        match_count = result.get("match_count", 0)
        flag_count  = result.get("flag_count", 0)
        flagged     = result.get("flagged", [])
        file_content= result.get("file_content", "")
        formatted   = result.get("formatted", "")
        existing    = {f.rule_id for f in findings}

        # For dependency checks with flags — always reason about them
        has_findings_to_reason = (match_count > 0 or flag_count > 0 or len(flagged) > 0)

        if not has_findings_to_reason and not file_content:
            return {"confidence": 0.92, "goal_met": False, "reason": f"No issues in {file_path}."}

        # Build evidence block
        evidence_block = ""
        if formatted:
            evidence_block += f"Pattern matches:\n{formatted}\n\n"
        if flagged:
            evidence_block += f"Dependency flags:\n{json.dumps(flagged, indent=2)}\n\n"
        if file_content and not has_findings_to_reason:
            # Include file content for LLM to do its own review even without regex hits
            evidence_block += f"File content (review manually for subtle issues):\n{file_content[:2000]}\n\n"

        rules_block = self.policy.get_rules_for_prompt()
        ctx_block   = self.policy.get_context_prompt()
        threshold   = self._cfg.confidence_threshold

        system_prompt = (
            "You are a security analysis agent in HoneySentinel-OS. "
            "Your job is to find real security vulnerabilities. "
            "Be thorough — do not dismiss findings without good reason. "
            "CRITICAL: Set overall_confidence to your TRUE confidence (0.0 to 1.0). Only set >= 0.95 if you are ABSOLUTELY certain. For anything ambiguous, set lower and write a human_question — the analyst MUST review. Output ONLY valid JSON with no markdown fences."
            "Output ONLY valid JSON with no markdown fences."
        )

        user_prompt = (
            f"{ctx_block}\n\n"
            f"{rules_block}\n\n"
            f"FILE BEING ANALYSED: {file_path}\n"
            f"LANGUAGE: {_ext_to_lang(file_path)}\n\n"
            f"TOOL EVIDENCE:\n{evidence_block}\n"
            f"ALREADY FOUND (do not duplicate these rule IDs): {list(existing)}\n\n"
            f"INSTRUCTIONS:\n"
            f"1. For each piece of evidence, decide if it is a true positive security issue.\n"
            f"2. Consider the project context: {self.policy.context.authentication_type} auth, "
            f"{self.policy.context.data_sensitivity} sensitivity data, handles_pii={self.policy.context.handles_pii}.\n"
            f"3. If confidence < {threshold}: you MUST set human_question. Do not leave it empty.\n"
            f"4. Be aggressive about finding issues — this is a security tool.\n\n"
            f"RESPOND WITH THIS EXACT JSON STRUCTURE:\n"
            f'{{"findings":[{{"rule_id":"RULE_ID","severity":"critical|high|medium|low|info",'
            f'"title":"Short title","description":"Detailed explanation of the vulnerability",'
            f'"evidence":"The exact code or config that is problematic",'
            f'"recommendation":"Specific fix instructions",'
            f'"confidence":0.85,"false_positive_risk":"Why this might not be an issue",'
            f'"is_true_positive":true}}],'
            f'"overall_confidence":0.85,'
            f'"human_question":"REQUIRED if confidence < {threshold}: what is uncertain about this finding?",'
            f'"human_options":["Option 1","Option 2"]}}'
        )

        raw = await self._llm_call(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=2000,
            temperature=0.1,
        )
        ev = _parse_json_safe(raw, default={"findings": [], "overall_confidence": 0.5})

        new_findings_count = 0
        for fd in ev.get("findings", []):
            if not fd.get("is_true_positive", True):
                continue
            if fd.get("rule_id") in existing:
                continue
            evidence_val = fd.get("evidence", "")
            if not isinstance(evidence_val, str):
                evidence_val = json.dumps(evidence_val)
            # Look up CWE from policy rule
            rule_obj = self.policy.get_rule(fd.get("rule_id", ""))
            await self.memory.add_finding(self.session_id, Finding(
                agent_id=self.agent_id,
                file_path=file_path,
                rule_id=fd.get("rule_id", "UNKNOWN"),
                severity=_parse_severity(fd.get("severity", "medium")),
                title=fd.get("title", "Security issue"),
                description=fd.get("description", ""),
                evidence=evidence_val[:500],
                recommendation=fd.get("recommendation", ""),
                confidence=float(fd.get("confidence", 0.5)),
                false_positive_risk=fd.get("false_positive_risk", ""),
                cwe_id=rule_obj.cwe_id if rule_obj else fd.get("cwe_id", ""),
                cwe_name=rule_obj.cwe_name if rule_obj else fd.get("cwe_name", ""),
                owasp=rule_obj.owasp if rule_obj else fd.get("owasp", ""),
            ))
            new_findings_count += 1

        overall_conf = float(ev.get("overall_confidence", 0.85))

        return {
            "confidence":     overall_conf,
            "goal_met":       False,
            "reason":         f"Analysed {file_path}. Wrote {new_findings_count} findings.",
            "human_question": ev.get("human_question", ""),
            "human_options":  ev.get("human_options", []),
        }

    # -- Should stop -----------------------------------------------------------

    async def _should_stop(self, state: AgentState, evaluation: dict) -> bool:
        if evaluation.get("goal_met"):
            return True
        remaining = [f for f in self._files_todo if f not in self._files_done]
        return len(remaining) == 0


# -- Helpers -------------------------------------------------------------------

def _ext_to_lang(file_path: str) -> str:
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
        ".go": "go", ".yaml": "yaml", ".yml": "yaml",
        ".json": "json", ".env": "env", ".toml": "toml",
    }
    ext = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    return ext_map.get(ext, "unknown")


def _parse_severity(raw: str) -> Severity:
    m = {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    }
    return m.get(raw.lower(), Severity.MEDIUM)


def _parse_json_safe(raw: str, default: dict) -> dict:
    try:
        clean = raw.strip()
        if clean.startswith("```"):
            parts = clean.split("```")
            clean = parts[1] if len(parts) > 1 else clean
            if clean.startswith("json"):
                clean = clean[4:]
        return json.loads(clean)
    except Exception:
        return default
