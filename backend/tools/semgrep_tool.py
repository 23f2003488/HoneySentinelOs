"""
HoneySentinel-OS -- Semgrep Tool
Runs Semgrep if installed, falls back to pattern_detector gracefully.
When Semgrep is installed: pip install semgrep
Results are structured identically either way so agents don't care which ran.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from backend.policy import get_policy_engine

logger = logging.getLogger(__name__)

SEMGREP_AVAILABLE = shutil.which("semgrep") is not None


class SemgrepTool:
    """
    Wraps Semgrep for baseline SAST scanning.
    Falls back to pattern_detector if Semgrep not installed.
    Agents call scan() and get a normalised result dict either way.
    """

    def __init__(self):
        self.policy = get_policy_engine()
        if SEMGREP_AVAILABLE:
            logger.info("SemgrepTool: Semgrep found — using real SAST engine")
        else:
            logger.info("SemgrepTool: Semgrep not found — using pattern detector fallback")

    def scan(self, repo_path: str, agent_id: str = "unknown") -> dict:
        """
        Scan a directory. Returns normalised findings list.
        Each finding: {rule_id, severity, file, line, message, cwe_id}
        """
        start = time.time()
        if SEMGREP_AVAILABLE:
            return self._run_semgrep(repo_path, start)
        else:
            return self._run_pattern_fallback(repo_path, start)

    def _run_semgrep(self, repo_path: str, start: float) -> dict:
        try:
            # We add --no-git-ignore and --metrics=off for better reliability in temp folders
            result = subprocess.run(
                [
                    "semgrep",
                    "scan",
                    "--config", "auto",
                    "--json",
                    "--quiet",
                    "--metrics=off",
                    "--no-git-ignore", 
                    repo_path,
                ],
                capture_output=True,
                text=True,
                timeout=300, # Increased timeout for larger repos
            )
            
            raw = json.loads(result.stdout or "{}")
            findings = []
            for r in raw.get("results", []):
                # Map semgrep rule ID to our policy IDs if possible, else keep generic
                rule_id = r.get("check_id", "UNKNOWN").split(".")[-1].upper()
                findings.append({
                    "rule_id":   rule_id,
                    "severity":  r.get("extra", {}).get("severity", "WARNING").lower(),
                    "file":      r.get("path", ""),
                    "line":      r.get("start", {}).get("line", 0),
                    "message":   r.get("extra", {}).get("message", ""),
                    "code":      r.get("extra", {}).get("lines", ""),
                    "cwe_id":    self._extract_cwe(r),
                    "engine":    "semgrep",
                })
            duration_ms = int((time.time() - start) * 1000)
            logger.info(f"Semgrep found {len(findings)} results in {duration_ms}ms")
            return {
                "findings": findings,
                "total": len(findings),
                "engine": "semgrep",
                "duration_ms": duration_ms,
                "error": None,
            }
        except subprocess.TimeoutExpired:
            logger.error("Semgrep timed out after 300s — falling back to pattern detector")
            return self._run_pattern_fallback(repo_path, start)
        except Exception as e:
            logger.error(f"Semgrep failed: {e} — falling back to pattern detector")
            return self._run_pattern_fallback(repo_path, start)

    def _run_pattern_fallback(self, repo_path: str, start: float) -> dict:
        """Use our own pattern detector across all files."""
        from backend.tools.file_scanner import FileScannerTool
        from backend.tools.pattern_detector import PatternDetectorTool

        scanner  = FileScannerTool()
        detector = PatternDetectorTool()
        scan_result = scanner.scan_directory(repo_path)
        findings = []

        for file_info in scan_result.get("files", []):
            if file_info.get("is_binary"):
                continue
            rel_path = file_info["path"]
            fc = scanner.read_file_content(repo_path, rel_path)
            if "error" in fc:
                continue
            content  = fc.get("content", "")
            language = file_info.get("file_type", "unknown")
            scan     = detector.scan_content(rel_path, content, language)
            for match in scan.matches:
                rule = self.policy.get_rule(match.rule_id)
                findings.append({
                    "rule_id":  match.rule_id,
                    "severity": rule.severity if rule else "medium",
                    "file":     rel_path,
                    "line":     match.line_number,
                    "message":  match.line_content.strip()[:200],
                    "code":     "\n".join(match.context_lines),
                    "cwe_id":   rule.cwe_id if rule else "",
                    "engine":   "pattern_detector",
                })

        duration_ms = int((time.time() - start) * 1000)
        logger.info(f"Pattern detector found {len(findings)} results in {duration_ms}ms")
        return {
            "findings": findings,
            "total": len(findings),
            "engine": "pattern_detector",
            "duration_ms": duration_ms,
            "error": None,
        }

    def _extract_cwe(self, semgrep_result: dict) -> str:
        """Extract CWE from semgrep metadata if present."""
        metadata = semgrep_result.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe", [])
        if isinstance(cwe, list) and cwe:
            return cwe[0]
        if isinstance(cwe, str):
            return cwe
        return ""

    def format_for_prompt(self, scan_result: dict) -> str:
        """Format scan results as human-readable text for agent prompts."""
        findings = scan_result.get("findings", [])
        engine   = scan_result.get("engine", "unknown")
        if not findings:
            return f"No issues found by {engine}."
        lines = [f"SAST scan ({engine}) found {len(findings)} potential issues:\n"]
        for i, f in enumerate(findings[:20], 1):
            cwe = f" [{f['cwe_id']}]" if f.get("cwe_id") else ""
            lines.append(
                f"{i}. [{f['severity'].upper()}]{cwe} {f['rule_id']} "
                f"in {f['file']} line {f['line']}\n"
                f"   {f['message'][:150]}"
            )
        return "\n".join(lines)
