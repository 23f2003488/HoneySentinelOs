"""
HoneySentinel-OS — Emergency Patch Script
Run this from your honeySentinel root directory:
    python patch.py

This rewrites the broken files directly and clears all __pycache__ folders.
No manual file replacement needed.
"""

import os
import shutil
from pathlib import Path

ROOT = Path(__file__).parent
print(f"Patching HoneySentinel in: {ROOT}")

# ── Step 1: Nuke ALL __pycache__ folders ──────────────────────────────────────
removed = 0
for cache in ROOT.rglob("__pycache__"):
    shutil.rmtree(cache)
    removed += 1
for pyc in ROOT.rglob("*.pyc"):
    pyc.unlink()
    removed += 1
print(f"  Removed {removed} cache files/folders")

# ── Step 2: Rewrite file_scanner.py completely ────────────────────────────────

FILE_SCANNER = '''"""
HoneySentinel-OS — Tool: file_scanner
Walks a local directory or extracted zip and returns a structured file list.
No LLM. Pure filesystem traversal filtered by policy scope.
Called by ReconAgent during its act() step.
"""

from __future__ import annotations

import os
import zipfile
import tempfile
import time
from pathlib import Path
from typing import Optional

from backend.memory import FileNode, RepoMap
from backend.policy import get_policy_engine


LANGUAGE_MAP = {
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "typescript",
    ".jsx":  "javascript",
    ".tsx":  "typescript",
    ".java": "java",
    ".go":   "go",
    ".yaml": "yaml",
    ".yml":  "yaml",
    ".json": "json",
    ".toml": "toml",
    ".env":  "env",
    ".ini":  "ini",
    ".cfg":  "ini",
    ".txt":  "text",
    ".md":   "markdown",
    ".html": "html",
    ".css":  "css",
    ".sh":   "shell",
}

ENTRY_POINT_NAMES = {
    "main.py", "app.py", "server.py", "index.py",
    "index.js", "index.ts", "app.js", "server.js",
    "main.go", "main.java",
}


class FileScannerTool:
    """
    Scans a directory or zip file and returns structured file data.
    Respects policy scope rules (extensions, excluded paths, size limits).
    """

    def __init__(self):
        self.policy = get_policy_engine()

    def scan_directory(self, root_path: str) -> dict:
        """
        Main entry point for ReconAgent.
        Auto-detects zip files — if root_path ends in .zip, extracts and scans.
        """
        # KEY FIX: automatically handle zip files
        if str(root_path).lower().endswith(".zip"):
            return self.scan_zip(root_path)

        start = time.time()
        root = Path(root_path)

        if not root.exists():
            return {"error": f"Path does not exist: {root_path}"}

        if not root.is_dir():
            return {"error": f"Path is not a directory: {root_path}"}

        files = []
        languages_seen = set()
        entry_points = []
        config_files = []
        skipped = 0

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue

            rel_path = str(file_path.relative_to(root))
            size_bytes = file_path.stat().st_size

            if not self.policy.is_in_scope(rel_path, size_bytes):
                skipped += 1
                continue

            ext = file_path.suffix.lower()
            lang = LANGUAGE_MAP.get(ext, "unknown")
            is_binary = _is_binary(file_path)

            node = FileNode(
                path=rel_path,
                file_type=lang,
                size_bytes=size_bytes,
                is_binary=is_binary,
                metadata={"extension": ext},
            )
            files.append(node)

            if lang != "unknown":
                languages_seen.add(lang)

            if file_path.name in ENTRY_POINT_NAMES:
                entry_points.append(rel_path)

            if lang in ("yaml", "env", "ini", "toml", "json") or file_path.name in (
                "Dockerfile", ".env", ".env.example", "docker-compose.yml"
            ):
                config_files.append(rel_path)

        duration_ms = int((time.time() - start) * 1000)

        return {
            "root_path": str(root_path),
            "files": [f.__dict__ for f in files],
            "total_files": len(files),
            "skipped_files": skipped,
            "languages_detected": sorted(languages_seen),
            "entry_points": entry_points,
            "config_files": config_files,
            "scan_duration_ms": duration_ms,
        }

    def scan_zip(self, zip_path: str) -> dict:
        """
        Extract zip to a persistent temp directory then scan it.
        Uses mkdtemp (not TemporaryDirectory) so files survive beyond this call.
        """
        if not zipfile.is_zipfile(zip_path):
            return {"error": f"Not a valid zip file: {zip_path}"}

        # PERSISTENT temp dir — AnalysisAgent reads files from here later
        tmp_dir = tempfile.mkdtemp(prefix="honeySentinel_extracted_")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmp_dir)

        # If zip has a single top-level folder, use that as the root
        entries = list(Path(tmp_dir).iterdir())
        if len(entries) == 1 and entries[0].is_dir():
            tmp_dir = str(entries[0])

        result = self.scan_directory(tmp_dir)
        result["source_zip"] = zip_path
        return result

    def read_file_content(self, root_path: str, rel_path: str) -> dict:
        """
        Read a single file\'s content for AnalysisAgent.
        root_path is repo_map.root_path (the extracted temp dir for zips).
        """
        full_path = Path(root_path) / rel_path
        if not full_path.exists():
            return {"error": f"File not found: {rel_path}"}

        size = full_path.stat().st_size
        if not self.policy.is_in_scope(rel_path, size):
            return {"error": f"File out of scope: {rel_path}"}

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            truncated = len(content) > 8000
            return {
                "path": rel_path,
                "content": content[:8000],
                "truncated": truncated,
                "size_bytes": size,
                "lines": content.count("\\n") + 1,
            }
        except Exception as e:
            return {"error": f"Could not read {rel_path}: {e}"}


def _is_binary(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:512]
        return b"\\x00" in chunk
    except Exception:
        return False
'''

# ── Step 3: Rewrite recon_agent.py completely ─────────────────────────────────

RECON_AGENT = '''"""
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
                f"File scan completed: {self._scan_result.get(\'total_files\', 0)} files found, "
                f"{self._scan_result.get(\'skipped_files\', 0)} skipped. "
                f"Languages: {self._scan_result.get(\'languages_detected\', [])}. "
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
                "reason": f"Scan failed: {result[\'error\']}",
                "human_question": f"The file scanner failed: {result[\'error\']}. Should I retry or stop?",
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
'''

# ── Step 4: Rewrite analysis_agent.py to use repo_map.root_path ──────────────

ANALYSIS_AGENT_PATCH = '''        # Read file content using repo_map.root_path (correct for extracted zips)
        start = time.time()
        repo_map = await self.memory.get_repo_map(self.session_id)
        read_root = repo_map.root_path if repo_map else self.repo_path
        fc = self._scanner.read_file_content(read_root, file_path)'''

# Write the files
target_scanner = ROOT / "backend" / "tools" / "file_scanner.py"
target_recon   = ROOT / "backend" / "agents" / "recon_agent.py"
target_analysis= ROOT / "backend" / "agents" / "analysis_agent.py"

target_scanner.write_text(FILE_SCANNER, encoding="utf-8")
print(f"  Wrote {target_scanner}")

target_recon.write_text(RECON_AGENT, encoding="utf-8")
print(f"  Wrote {target_recon}")

# Patch analysis_agent — replace the read_file_content call
analysis_content = target_analysis.read_text(encoding="utf-8")
OLD = "        # Read file content\n        start   = time.time()\n        fc      = self._scanner.read_file_content(self.repo_path, file_path)"
OLD2 = "        # Read file content — use root_path from RepoMap (correct for both dirs and extracted zips)\n        start    = time.time()\n        repo_map = await self.memory.get_repo_map(self.session_id)\n        read_root = repo_map.root_path if repo_map else self.repo_path\n        fc       = self._scanner.read_file_content(read_root, file_path)"

if OLD in analysis_content:
    analysis_content = analysis_content.replace(OLD, ANALYSIS_AGENT_PATCH, 1)
    target_analysis.write_text(analysis_content, encoding="utf-8")
    print(f"  Patched {target_analysis}")
elif OLD2 in analysis_content or "read_root" in analysis_content:
    print(f"  {target_analysis} already patched — skipping")
else:
    print(f"  WARNING: Could not find patch target in {target_analysis}")
    print("  analysis_agent.py — look for 'read_file_content' and change self.repo_path to read_root")

print()
print("=" * 50)
print("PATCH COMPLETE")
print("=" * 50)
print()
print("Now restart uvicorn:")
print("  uvicorn backend.api.main:app --port 8000")
print()
print("Do NOT use --reload flag. Use plain --port 8000 only.")
