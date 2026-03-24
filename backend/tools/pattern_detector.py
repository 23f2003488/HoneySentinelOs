"""
HoneySentinel-OS — Tool: pattern_detector
Runs deterministic pattern matching on file content.
Used by AnalysisAgent to find concrete evidence before LLM reasoning.
No LLM here — pure regex + keyword scanning.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional

from backend.policy import get_policy_engine, SecurityRule


# ─── Rule → Regex Patterns ────────────────────────────────────────────────────
# These are real regexes for initial evidence gathering.
# The LLM then reasons over the matches to determine true positives.

RULE_PATTERNS: dict[str, list[str]] = {
    "HARDCODED_SECRET": [
        r'(?i)(password|passwd|pwd|secret|api[_\-]?key|token|private[_\-]?key)\s*=\s*["\'][^"\']{6,}["\']',
        r'(?i)(aws|azure|gcp|github|stripe|twilio)[_\-]?(key|secret|token)\s*=\s*["\'][^"\']{8,}["\']',
        r'(?i)bearer\s+[a-zA-Z0-9\-_]{20,}',
        r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
    ],
    "SQL_INJECTION": [
        r'(?i)(execute|query|cursor\.execute)\s*\(\s*[f"\'](SELECT|INSERT|UPDATE|DELETE)',
        r'(?i)(SELECT|INSERT|UPDATE|DELETE).*\+\s*\w+',
        r'(?i)\.format\(.*\)\s*#.*sql',
        r'(?i)f["\'].*\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b.*{',
    ],
    "INSECURE_DESERIALIZATION": [
        r'pickle\.loads?\s*\(',
        r'yaml\.load\s*\([^)]*\)',          # yaml.load without SafeLoader
        r'\beval\s*\(',
        r'\bexec\s*\(',
        r'marshal\.loads?\s*\(',
        r'shelve\.open\s*\(',
    ],
    "BROKEN_AUTH": [
        r'(?i)jwt\.decode\s*\([^)]*verify\s*=\s*False',
        r'(?i)algorithm\s*=\s*["\']none["\']',
        r'(?i)verify\s*=\s*False',
        r'(?i)SECRET_KEY\s*=\s*["\'][^"\']{0,10}["\']',    # weak secret
    ],
    "SENSITIVE_DATA_EXPOSURE": [
        r'(?i)(logger|logging|print)\s*\(.*\b(password|passwd|secret|token|ssn|credit.?card)\b',
        r'(?i)return\s+.*\bpassword\b',
        r'(?i)response\s*\[.*\bpassword\b',
    ],
    "INSECURE_DIRECT_OBJECT_REF": [
        r'(?i)(user_id|account_id|customer_id)\s*=\s*request\.(args|form|json|data)',
        r'(?i)get_object_or_404\([^,]+,\s*id\s*=\s*request',
    ],
    "MISSING_RATE_LIMIT": [
        r'(?i)@app\.route\s*\(["\']/(login|register|signup|reset.?password|forgot)',
        r'(?i)@router\.(post|get)\s*\(["\']/(auth|login|register)',
    ],
    "MISCONFIGURED_CORS": [
        r'(?i)allow[_\-]?origins?\s*[=:]\s*[\[\(]?\s*["\']?\*["\']?',
        r'(?i)Access-Control-Allow-Origin["\']?\s*[,:]?\s*["\']?\*',
        r'(?i)CORSMiddleware.*allow_origins.*\*',
    ],
    "INSECURE_CONFIG": [
        r'(?i)DEBUG\s*=\s*True',
        r'(?i)debug\s*:\s*true',
        r'(?i)ALLOWED_HOSTS\s*=\s*\[.*\*.*\]',
    ],
}


@dataclass
class PatternMatch:
    rule_id: str
    line_number: int
    line_content: str
    matched_pattern: str
    context_lines: list[str] = field(default_factory=list)  # ±2 lines around match


@dataclass
class PatternScanResult:
    file_path: str
    matches: list[PatternMatch] = field(default_factory=list)
    rules_checked: list[str] = field(default_factory=list)
    scan_duration_ms: int = 0
    error: Optional[str] = None

    def has_matches(self) -> bool:
        return len(self.matches) > 0

    def matches_for_rule(self, rule_id: str) -> list[PatternMatch]:
        return [m for m in self.matches if m.rule_id == rule_id]

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "match_count": len(self.matches),
            "rules_checked": self.rules_checked,
            "scan_duration_ms": self.scan_duration_ms,
            "error": self.error,
            "matches": [
                {
                    "rule_id": m.rule_id,
                    "line": m.line_number,
                    "content": m.line_content.strip()[:200],
                    "context": [l.strip() for l in m.context_lines],
                }
                for m in self.matches
            ],
        }


class PatternDetectorTool:
    """
    Scans file content for security patterns defined per rule.
    Returns structured matches that AnalysisAgent reasons over with the LLM.
    """

    def __init__(self):
        self.policy = get_policy_engine()
        self._compiled: dict[str, list[re.Pattern]] = {
            rule_id: [re.compile(p, re.MULTILINE) for p in patterns]
            for rule_id, patterns in RULE_PATTERNS.items()
        }

    def scan_content(
        self,
        file_path: str,
        content: str,
        language: Optional[str] = None,
    ) -> PatternScanResult:
        """
        Scan file content against all enabled rules for this language.
        Returns PatternScanResult with matches and context.
        """
        start = time.time()
        result = PatternScanResult(file_path=file_path)

        # Only scan rules enabled for this language
        active_rules = self.policy.get_enabled_rules(language)
        result.rules_checked = [r.id for r in active_rules]

        lines = content.splitlines()

        for rule in active_rules:
            patterns = self._compiled.get(rule.id, [])
            for pattern in patterns:
                for m in pattern.finditer(content):
                    # Calculate line number
                    line_num = content[: m.start()].count("\n") + 1
                    line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                    # Skip if it matches a false positive signal
                    if self._is_false_positive_hint(line_content, rule):
                        continue

                    # Gather ±2 context lines
                    ctx_start = max(0, line_num - 3)
                    ctx_end   = min(len(lines), line_num + 2)
                    ctx_lines = lines[ctx_start:ctx_end]

                    result.matches.append(PatternMatch(
                        rule_id         = rule.id,
                        line_number     = line_num,
                        line_content    = line_content,
                        matched_pattern = pattern.pattern[:80],
                        context_lines   = ctx_lines,
                    ))

        result.scan_duration_ms = int((time.time() - start) * 1000)
        return result

    def _is_false_positive_hint(self, line: str, rule: SecurityRule) -> bool:
        """
        Check if the matched line contains a false positive signal from policy.
        These are plain-text signals, not regexes — fast string search.
        """
        line_lower = line.lower()
        for signal in rule.false_positive_signals:
            if signal.lower() in line_lower:
                return True
        return False

    def format_matches_for_prompt(self, result: PatternScanResult) -> str:
        """
        Format scan results as a concise block for injection into LLM prompts.
        AnalysisAgent uses this as its 'observation' for reasoning.
        """
        if not result.has_matches():
            return f"No pattern matches found in {result.file_path}."

        lines = [f"Pattern scan results for {result.file_path}:"]
        for m in result.matches:
            lines.append(
                f"\n  [{m.rule_id}] Line {m.line_number}:\n"
                f"    Code: {m.line_content.strip()[:150]}\n"
                f"    Context:\n" +
                "\n".join(f"      {l.strip()}" for l in m.context_lines)
            )
        return "\n".join(lines)
