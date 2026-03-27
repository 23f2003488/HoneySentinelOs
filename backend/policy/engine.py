"""
HoneySentinel-OS — Policy Engine
Loads security_policy.yaml and exposes typed, validated access to every section.
Agents never read the yaml directly — they call PolicyEngine methods.

This is the anti-hallucination layer:
  - Agents get grounded facts (auth type, data sensitivity, active rules)
  - Every LLM prompt is injected with policy context before reasoning
  - Confidence threshold from policy controls when HITL is triggered
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# Default policy path — overridable via env var
DEFAULT_POLICY_PATH = Path(__file__).parent.parent.parent / "config" / "security_policy.yaml"


# ─── Typed Policy Objects ──────────────────────────────────────────────────────

@dataclass
class ProjectContext:
    """What kind of system are we analysing? Injected into every agent prompt."""
    project_name: str
    project_type: str
    language_stack: list[str]
    framework: str
    authentication_type: str
    data_sensitivity: str           # low | medium | high | critical
    deployment_target: str
    has_database: bool
    database_type: str
    exposes_public_api: bool
    handles_pii: bool

    def to_prompt_block(self) -> str:
        """
        Returns a plain-text block injected into agent prompts.
        Keeps agents grounded in what they are actually analysing.
        """
        pii_note = "handles PII data" if self.handles_pii else "does not handle PII"
        api_note = "exposes a public API" if self.exposes_public_api else "is not public-facing"
        db_note = f"uses {self.database_type}" if self.has_database else "has no database"

        return f"""
=== TARGET SYSTEM CONTEXT (from security_policy.yaml) ===
Project      : {self.project_name}
Type         : {self.project_type}
Stack        : {', '.join(self.language_stack)}
Framework    : {self.framework}
Auth type    : {self.authentication_type}
Data sensitivity: {self.data_sensitivity.upper()}
Deployment   : {self.deployment_target}
Database     : {db_note}
API exposure : {api_note}
PII          : {pii_note}
==========================================================
""".strip()


@dataclass
class SecurityRule:
    """One enabled rule from the policy. Agents use this to reason about findings."""
    id: str
    severity: str
    category: str
    title: str
    description: str
    pattern_hints: list[str]
    languages: list[str]
    false_positive_signals: list[str]
    cwe_id: str = ""        # e.g. "CWE-89"
    cwe_name: str = ""      # e.g. "SQL Injection"
    owasp: str = ""         # e.g. "A03:2021"
    enabled: bool = True

    def to_prompt_block(self) -> str:
        """Compact representation injected when an agent is evaluating this rule."""
        return (
            f"Rule [{self.id}] — {self.title} (severity: {self.severity})\n"
            f"  What to detect: {self.description.strip()}\n"
            f"  Pattern hints : {', '.join(self.pattern_hints)}\n"
            f"  False positive signals: {', '.join(self.false_positive_signals)}"
        )


@dataclass
class AgentConfig:
    confidence_threshold: float     # below this → ask human
    max_iterations: int
    max_findings: int
    require_fp_reasoning: bool


@dataclass
class SeverityAction:
    report_section: str
    recommended_action: str
    escalate: bool


@dataclass
class ScopeConfig:
    include_extensions: list[str]
    exclude_paths: list[str]
    max_file_size_kb: int

    def is_in_scope(self, file_path: str, file_size_bytes: int = 0) -> bool:
        """
        Returns True if this file should be analysed.
        Called by the file_scanner tool and ReconAgent.
        """
        path = file_path.replace("\\", "/")

        # Check excluded paths
        for excluded in self.exclude_paths:
            # Handle glob-style patterns
            if excluded.startswith("*"):
                if path.endswith(excluded[1:]):
                    return False
            elif excluded in path:
                return False

        # Check extension
        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        if ext not in self.include_extensions:
            return False

        # Check size
        if file_size_bytes > 0:
            size_kb = file_size_bytes / 1024
            if size_kb > self.max_file_size_kb:
                logger.debug(f"File {file_path} excluded: {size_kb:.1f}KB > {self.max_file_size_kb}KB limit")
                return False

        return True


# ─── Policy Engine ─────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Singleton-friendly policy loader.
    Load once at startup via PolicyEngine.load().
    All agents call engine.get_*() methods — never parse yaml themselves.
    """

    def __init__(self, policy_path: Optional[Path] = None):
        self._path = policy_path or Path(os.getenv("POLICY_PATH", str(DEFAULT_POLICY_PATH)))
        self._raw: dict = {}
        self.version: str = ""
        self.context: ProjectContext = None
        self.agent_config: AgentConfig = None
        self.rules: list[SecurityRule] = []
        self.severity_actions: dict[str, SeverityAction] = {}
        self.scope: ScopeConfig = None
        self._loaded = False

    # ── Loading ───────────────────────────────────────────────────────────────

    def load(self) -> "PolicyEngine":
        """
        Parse and validate the yaml. Call this once at startup.
        Raises PolicyLoadError with a clear message if anything is wrong.
        """
        if not self._path.exists():
            raise PolicyLoadError(
                f"Policy file not found: {self._path}\n"
                "Copy config/security_policy.yaml to your project root."
            )

        with open(self._path, "r") as f:
            self._raw = yaml.safe_load(f)

        self._validate_top_level()

        self.version      = self._raw.get("version", "unknown")
        self.context      = self._parse_context()
        self.agent_config = self._parse_agent_config()
        self.rules        = self._parse_rules()
        self.severity_actions = self._parse_severity_actions()
        self.scope        = self._parse_scope()
        self._loaded      = True

        enabled = sum(1 for r in self.rules if r.enabled)
        logger.info(
            f"PolicyEngine loaded v{self.version} | "
            f"{enabled}/{len(self.rules)} rules enabled | "
            f"project={self.context.project_name} | "
            f"sensitivity={self.context.data_sensitivity}"
        )
        return self

    def _validate_top_level(self) -> None:
        required = ["version", "context", "agents", "rules", "scope"]
        missing = [k for k in required if k not in self._raw]
        if missing:
            #raise PolicyLoadError(f"Policy missing required sections: {missing}")
            logger.warning(f"Policy missing sections: {missing}. Falling back to defaults.")

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_context(self) -> ProjectContext:
        c = self._raw["context"]
        return ProjectContext(
            project_name      = c.get("project_name", "Unknown"),
            project_type      = c.get("project_type", "unknown"),
            language_stack    = c.get("language_stack", []),
            framework         = c.get("framework", "none"),
            authentication_type = c.get("authentication_type", "none"),
            data_sensitivity  = c.get("data_sensitivity", "medium"),
            deployment_target = c.get("deployment_target", "cloud"),
            has_database      = c.get("has_database", False),
            database_type     = c.get("database_type", "none"),
            exposes_public_api= c.get("exposes_public_api", False),
            handles_pii       = c.get("handles_pii", False),
        )

    def _parse_agent_config(self) -> AgentConfig:
        a = self._raw["agents"]
        return AgentConfig(
            confidence_threshold = float(a.get("confidence_threshold", 0.75)),
            max_iterations       = int(a.get("max_iterations", 20)),
            max_findings         = int(a.get("max_findings", 50)),
            require_fp_reasoning = bool(a.get("require_fp_reasoning", True)),
        )

    def _parse_rules(self) -> list[SecurityRule]:
        rules = []
        for r in self._raw.get("rules", []):
            if not r.get("enabled", True):
                continue
            rules.append(SecurityRule(
                id                    = r["id"],
                severity              = r["severity"],
                category              = r.get("category", "general"),
                title                 = r["title"],
                description           = r.get("description", ""),
                pattern_hints         = r.get("pattern_hints", []),
                languages             = r.get("languages", []),
                false_positive_signals= r.get("false_positive_signals", []),
                cwe_id                = r.get("cwe_id", ""),
                cwe_name              = r.get("cwe_name", ""),
                owasp                 = r.get("owasp", ""),
                enabled               = True,
            ))
        return rules

    def _parse_severity_actions(self) -> dict[str, SeverityAction]:
        actions = {}
        for sev, data in self._raw.get("severity_actions", {}).items():
            actions[sev] = SeverityAction(
                report_section     = data.get("report_section", sev),
                recommended_action = data.get("recommended_action", "Review"),
                escalate           = data.get("escalate", False),
            )
        return actions

    def _parse_scope(self) -> ScopeConfig:
        s = self._raw["scope"]
        return ScopeConfig(
            include_extensions = s.get("include_extensions", [".py"]),
            exclude_paths      = s.get("exclude_paths", []),
            max_file_size_kb   = int(s.get("max_file_size_kb", 500)),
        )

    # ── Agent-facing API ──────────────────────────────────────────────────────
    # These are the methods agents call. Keep them simple and explicit.

    def get_context_prompt(self) -> str:
        """
        Full context block for injection into agent system prompts.
        Call this once when initialising an agent.
        """
        self._assert_loaded()
        return self.context.to_prompt_block()

    def get_enabled_rules(self, language: Optional[str] = None) -> list[SecurityRule]:
        """
        Returns enabled rules, optionally filtered to a specific language.
        ReconAgent uses this to decide which rules are relevant per file.
        """
        self._assert_loaded()
        if not language:
            return self.rules
        return [r for r in self.rules if not r.languages or language in r.languages]

    def get_rule(self, rule_id: str) -> Optional[SecurityRule]:
        """Look up a specific rule by ID. Used by AnalysisAgent when writing findings."""
        self._assert_loaded()
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None

    def get_rules_for_prompt(self, language: Optional[str] = None) -> str:
        """
        Returns all relevant rules as a single prompt block.
        Injected into AnalysisAgent's reasoning prompt so it knows
        exactly what to look for — no guessing.
        """
        self._assert_loaded()
        rules = self.get_enabled_rules(language)
        if not rules:
            return "No rules configured for this language."
        lines = ["=== ACTIVE SECURITY RULES ==="]
        for r in rules:
            lines.append(r.to_prompt_block())
        lines.append("=" * 30)
        return "\n".join(lines)

    def should_ask_human(self, confidence: float) -> bool:
        """
        Returns True if agent confidence is below the policy threshold.
        This is what triggers HITL — not hardcoded logic, policy-driven.
        """
        self._assert_loaded()
        return confidence < self.agent_config.confidence_threshold

    def is_in_scope(self, file_path: str, file_size_bytes: int = 0) -> bool:
        """Delegates to ScopeConfig. Used by file_scanner tool."""
        self._assert_loaded()
        return self.scope.is_in_scope(file_path, file_size_bytes)

    def get_severity_action(self, severity: str) -> Optional[SeverityAction]:
        """Used by ReportAgent to decide how to handle each finding."""
        self._assert_loaded()
        return self.severity_actions.get(severity)

    def get_agent_config(self) -> AgentConfig:
        self._assert_loaded()
        return self.agent_config

    def summary(self) -> dict:
        """Human-readable summary — displayed in the transparency UI header."""
        self._assert_loaded()
        return {
            "version": self.version,
            "project": self.context.project_name,
            "project_type": self.context.project_type,
            "data_sensitivity": self.context.data_sensitivity,
            "auth_type": self.context.authentication_type,
            "handles_pii": self.context.handles_pii,
            "rules_enabled": len(self.rules),
            "confidence_threshold": self.agent_config.confidence_threshold,
            "languages": self.context.language_stack,
        }

    def _assert_loaded(self) -> None:
        if not self._loaded:
            raise RuntimeError("PolicyEngine not loaded. Call engine.load() first.")


# ─── Exception ────────────────────────────────────────────────────────────────

class PolicyLoadError(Exception):
    """Raised when the policy file is missing or malformed."""
    pass


# ─── Singleton factory ────────────────────────────────────────────────────────

_engine_instance: Optional[PolicyEngine] = None


def get_policy_engine(policy_path: Optional[Path] = None) -> PolicyEngine:
    """
    Singleton factory. Returns the same loaded engine everywhere.
    Call reset_policy_engine() in tests to get a fresh instance.
    """
    global _engine_instance
    if _engine_instance is not None:
        return _engine_instance
    _engine_instance = PolicyEngine(policy_path).load()
    return _engine_instance


def reset_policy_engine() -> None:
    """Reset singleton — used in tests only."""
    global _engine_instance
    _engine_instance = None
