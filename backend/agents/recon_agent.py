"""
HoneySentinel-OS — ReconAgent
Goal: build a complete RepoMap of the target and write it to shared memory.
Tools used: file_scanner.scan_directory (auto-handles zips)
Stops when: repo_map is complete and written to memory.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from backend.agents.base_agent import BaseAgent, _truncate
from backend.memory import AgentState, RepoMap, FileNode
from backend.tools import FileScannerTool

logger = logging.getLogger(__name__)


class ReconAgent(BaseAgent):

    def __init__(self, session_id: str, repo_path: str):
        super().__init__(
            agent_id="recon-001",
            agent_type="recon",
            goal="Scan the target repository, map all files within policy scope, and write the complete RepoMap to shared memory.",
            session_id=session_id,
        )
        self.repo_path = repo_path
        self._scanner = FileScannerTool()
        self._scan_result: dict = {}

    async def _observe(self, state: AgentState) -> str:
        repo_map = await self.memory.get_repo_map(self.session_id)
        if repo_map:
            return (
                f"RepoMap already exists in memory: {repo_map.total_files} files, "
                f"languages: {repo_map.languages_detected}. Goal is complete."
            )
        if self._scan_result:
            return (
                f"File scan completed: {self._scan_result.get('total_files', 0)} files found, "
                f"{self._scan_result.get('skipped_files', 0)} skipped. "
                f"Languages: {self._scan_result.get('languages_detected', [])}. "
                f"Need to write RepoMap to memory."
            )
        return (
            f"No RepoMap in memory yet. Target path: {self.repo_path}. "
            f"Need to scan the repository."
        )

    async def _plan(self, state: AgentState, observation: str) -> dict:
        if self._scan_result and not await self.memory.get_repo_map(self.session_id):
            return {
                "thought": "Scan complete. Writing RepoMap to shared memory.",
                "action": "write_repo_map",
                "action_input": {},
            }
        if await self.memory.get_repo_map(self.session_id):
            return {
                "thought": "RepoMap already in memory. Goal achieved.",
                "action": "stop",
                "action_input": {},
            }
        # First iteration — just scan, no LLM call needed
        return {
            "thought": f"Scanning {self.repo_path} for all in-scope files.",
            "action": "scan_repository",
            "action_input": {"path": self.repo_path},
        }

    async def _act(self, state: AgentState, plan: dict) -> Any:
        action = plan.get("action", "scan_repository")

        if action == "stop":
            return {"status": "already_done"}

        if action == "write_repo_map":
            return await self._write_repo_map()

        # scan_repository — scan_directory auto-handles zips
        start = time.time()
        result = self._scanner.scan_directory(self.repo_path)
        duration = int((time.time() - start) * 1000)

        await self._log_tool(
            tool_name="file_scanner.scan_directory",
            input_summary=f"path={self.repo_path}",
            output={
                "total_files": result.get("total_files"),
                "languages": result.get("languages_detected"),
                "skipped": result.get("skipped_files"),
                "source_zip": result.get("source_zip"),
            },
            duration_ms=duration,
            success="error" not in result,
            error=result.get("error"),
        )

        if "error" not in result:
            self._scan_result = result

        return result

    async def _write_repo_map(self) -> dict:
        raw = self._scan_result
        files = [
            FileNode(
                path=f["path"],
                file_type=f["file_type"],
                size_bytes=f["size_bytes"],
                is_binary=f.get("is_binary", False),
                metadata=f.get("metadata", {}),
            )
            for f in raw.get("files", [])
        ]
        repo_map = RepoMap(
            root_path=raw["root_path"],
            files=files,
            total_files=raw["total_files"],
            languages_detected=raw["languages_detected"],
            entry_points=raw["entry_points"],
            config_files=raw["config_files"],
            built_at=__import__("backend.memory.models", fromlist=["_now"])._now(),
        )
        await self.memory.set_repo_map(self.session_id, repo_map)
        return {
            "status": "repo_map_written",
            "total_files": repo_map.total_files,
            "languages": repo_map.languages_detected,
            "entry_points": repo_map.entry_points,
            "config_files": repo_map.config_files,
        }

    async def _evaluate(self, state: AgentState, plan: dict, result: Any) -> dict:
        if plan.get("action") == "stop" or (
            isinstance(result, dict) and result.get("status") in ("already_done", "repo_map_written")
        ):
            return {"confidence": 1.0, "goal_met": True, "reason": "RepoMap written to memory."}

        if isinstance(result, dict) and "error" in result:
            return {
                "confidence": 0.2,
                "goal_met": False,
                "reason": f"Scan failed: {result['error']}",
                "human_question": f"The file scanner failed: {result['error']}. Should I retry or stop?",
                "human_options": ["Retry the scan", "Stop and report error"],
            }

        total = result.get("total_files", 0)
        if total == 0:
            return {
                "confidence": 0.4,
                "goal_met": False,
                "reason": "No files found in scope.",
                "human_question": "No files were found in scope. Is the repository path or zip correct?",
                "human_options": ["Path is correct — continue anyway", "Stop — wrong path"],
            }

        return {
            "confidence": 0.95,
            "goal_met": False,
            "reason": f"Scan found {total} files. Will now write RepoMap to memory.",
        }

    async def _should_stop(self, state: AgentState, evaluation: dict) -> bool:
        if evaluation.get("goal_met"):
            return True
        repo_map = await self.memory.get_repo_map(self.session_id)
        return repo_map is not None


def _parse_json_safe(raw: str, default: dict) -> dict:
    try:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        return json.loads(clean)
    except Exception:
        return default
