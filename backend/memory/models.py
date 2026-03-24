"""
HoneySentinel-OS — Memory Models
All shared state lives here. Agents never pass data directly to each other;
they read from and write to these models via MemoryStore.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import uuid


# ─── Enums ────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentStatus(str, Enum):
    IDLE              = "idle"
    RUNNING           = "running"
    WAITING_FOR_HUMAN = "waiting_for_human"
    DONE              = "done"
    FAILED            = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class HITLStatus(str, Enum):
    PENDING  = "pending"
    ANSWERED = "answered"


class SessionStatus(str, Enum):
    INITIALIZING = "initializing"
    RUNNING      = "running"
    PAUSED       = "paused"       # waiting for human input
    DONE         = "done"
    FAILED       = "failed"


# ─── Core Models ──────────────────────────────────────────────────────────────

@dataclass
class FileNode:
    """One node in the repo file tree."""
    path: str
    file_type: str          # e.g. "python", "yaml", "javascript"
    size_bytes: int
    is_binary: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RepoMap:
    """Built by ReconAgent. All other agents read this before acting."""
    root_path: str
    files: list[FileNode]           = field(default_factory=list)
    total_files: int                = 0
    languages_detected: list[str]  = field(default_factory=list)
    entry_points: list[str]         = field(default_factory=list)   # main.py, app.py etc
    config_files: list[str]         = field(default_factory=list)   # *.yaml, *.env, Dockerfile
    built_at: Optional[str]         = None

    def to_dict(self) -> dict:
        return {
            "root_path": self.root_path,
            "files": [f.__dict__ for f in self.files],
            "total_files": self.total_files,
            "languages_detected": self.languages_detected,
            "entry_points": self.entry_points,
            "config_files": self.config_files,
            "built_at": self.built_at,
        }


@dataclass
class AgentState:
    """
    Live state of one agent. Every field is updated after each loop iteration.
    The transparency UI subscribes to changes in this model.
    """
    agent_id: str
    agent_type: str                 # "orchestrator" | "recon" | "analysis" | "report"
    goal: str

    # Loop state — updated every iteration
    status: AgentStatus             = AgentStatus.IDLE
    thought: str                    = ""       # current reasoning step
    last_action: str                = ""       # tool called or decision made
    last_observation: str           = ""       # what the tool returned (summary)
    decision: str                   = ""       # continue | ask_human | stop

    # Progress tracking
    iterations: int                 = 0
    max_iterations: int             = 20
    confidence: float               = 0.0      # 0.0 – 1.0, drives HITL threshold

    # Timing
    started_at: Optional[str]       = None
    updated_at: Optional[str]       = None
    finished_at: Optional[str]      = None

    # Subgoals queued by orchestrator
    pending_subgoals: list[str]     = field(default_factory=list)
    completed_subgoals: list[str]   = field(default_factory=list)

    def update(self, **kwargs) -> None:
        """Update fields and stamp updated_at. Does NOT increment iterations."""
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)
        self.updated_at = _now()

    def increment(self) -> None:
        """Call once per full agent loop iteration."""
        self.iterations += 1
        self.updated_at = _now()

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "goal": self.goal,
            "status": self.status.value,
            "thought": self.thought,
            "last_action": self.last_action,
            "last_observation": self.last_observation,
            "decision": self.decision,
            "iterations": self.iterations,
            "max_iterations": self.max_iterations,
            "confidence": self.confidence,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "finished_at": self.finished_at,
            "pending_subgoals": self.pending_subgoals,
            "completed_subgoals": self.completed_subgoals,
        }


@dataclass
class Finding:
    """
    A confirmed security issue. Written by AnalysisAgent, read by ReportAgent.
    Includes enough evidence for the report to explain its reasoning.
    """
    finding_id: str                 = field(default_factory=lambda: str(uuid.uuid4())[:8])
    agent_id: str                   = ""
    file_path: str                  = ""
    rule_id: str                    = ""        # matches security_policy.yaml rule
    severity: Severity              = Severity.MEDIUM
    title: str                      = ""
    description: str                = ""
    evidence: str                   = ""        # exact snippet or line reference
    recommendation: str             = ""
    confidence: float               = 0.0       # agent's self-reported confidence
    false_positive_risk: str        = ""        # agent's reasoning on FP risk
    timestamp: str                  = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "agent_id": self.agent_id,
            "file_path": self.file_path,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "false_positive_risk": self.false_positive_risk,
            "timestamp": self.timestamp,
        }


@dataclass
class HITLQuestion:
    """
    Created when an agent's confidence drops below the policy threshold.
    Agent sets status=WAITING_FOR_HUMAN, writes this, then pauses its loop.
    UI shows it. User answers. Agent resumes.
    """
    question_id: str                = field(default_factory=lambda: str(uuid.uuid4())[:8])
    agent_id: str                   = ""
    question: str                   = ""
    context: str                    = ""        # what triggered the uncertainty
    options: list[str]              = field(default_factory=list)   # optional suggested answers
    status: HITLStatus              = HITLStatus.PENDING
    answer: Optional[str]           = None
    asked_at: str                   = field(default_factory=_now)
    answered_at: Optional[str]      = None

    def answer_question(self, answer: str) -> None:
        self.answer = answer
        self.status = HITLStatus.ANSWERED
        self.answered_at = _now()

    def to_dict(self) -> dict:
        return {
            "question_id": self.question_id,
            "agent_id": self.agent_id,
            "question": self.question,
            "context": self.context,
            "options": self.options,
            "status": self.status.value,
            "answer": self.answer,
            "asked_at": self.asked_at,
            "answered_at": self.answered_at,
        }


@dataclass
class ToolResult:
    """
    Every tool invocation is logged here — not just the output, but the input
    hash and duration. Gives full auditability of what each agent actually did.
    """
    call_id: str                    = field(default_factory=lambda: str(uuid.uuid4())[:8])
    tool_name: str                  = ""
    agent_id: str                   = ""
    input_summary: str              = ""        # brief description, not raw input
    output: Any                     = None
    success: bool                   = True
    error: Optional[str]            = None
    duration_ms: int                = 0
    timestamp: str                  = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "tool_name": self.tool_name,
            "agent_id": self.agent_id,
            "input_summary": self.input_summary,
            "output": self.output,
            "success": self.success,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
        }


@dataclass
class SessionMeta:
    """Top-level session record — one per analysis run."""
    session_id: str                 = field(default_factory=lambda: str(uuid.uuid4())[:12])
    status: SessionStatus           = SessionStatus.INITIALIZING
    input_source: str               = ""        # blob path or local path
    input_type: str                 = ""        # "git_repo" | "uploaded_file" | "config"
    policy_version: str             = ""
    started_at: str                 = field(default_factory=_now)
    updated_at: Optional[str]       = None
    finished_at: Optional[str]      = None
    error: Optional[str]            = None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "status": self.status.value,
            "input_source": self.input_source,
            "input_type": self.input_type,
            "policy_version": self.policy_version,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "finished_at": self.finished_at,
            "error": self.error,
        }