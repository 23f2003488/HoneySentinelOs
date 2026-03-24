"""
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
        Read a single file's content for AnalysisAgent.
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
                "lines": content.count("\n") + 1,
            }
        except Exception as e:
            return {"error": f"Could not read {rel_path}: {e}"}


def _is_binary(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:512]
        return b"\x00" in chunk
    except Exception:
        return False
