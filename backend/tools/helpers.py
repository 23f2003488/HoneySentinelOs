"""
HoneySentinel-OS — Tools: yaml_parser + dependency_checker
Both are deterministic tools — no LLM.
yaml_parser: reads config files and extracts security-relevant fields.
dependency_checker: parses requirements.txt / package.json and flags outdated/risky packages.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional

import yaml


# ─── YAML Parser ──────────────────────────────────────────────────────────────

class YamlParserTool:
    """
    Parses yaml, json, toml, and .env config files.
    Extracts fields that are security-relevant for AnalysisAgent to reason over.
    """

    def parse_file(self, file_path: str, content: str) -> dict:
        """
        Parse a config file and return structured data + security flags.
        """
        ext = Path(file_path).suffix.lower()
        start = time.time()

        try:
            if ext in (".yaml", ".yml"):
                parsed = yaml.safe_load(content) or {}
                flags  = self._flag_yaml(parsed, file_path)
            elif ext == ".json":
                parsed = json.loads(content)
                flags  = self._flag_json(parsed, file_path)
            elif ext in (".env", ".env.example"):
                parsed = self._parse_dotenv(content)
                flags  = self._flag_env(parsed, file_path)
            else:
                parsed = {"raw": content[:2000]}
                flags  = []

            return {
                "file_path":    file_path,
                "parsed":       _safe_truncate(parsed),
                "security_flags": flags,
                "parse_ok":     True,
                "duration_ms":  int((time.time() - start) * 1000),
            }

        except Exception as e:
            return {
                "file_path":  file_path,
                "parse_ok":   False,
                "error":      str(e),
                "duration_ms": int((time.time() - start) * 1000),
            }

    def _flag_yaml(self, data: dict, path: str) -> list[dict]:
        flags = []
        flat  = _flatten(data)
        for key, val in flat.items():
            k = key.lower()
            v = str(val).lower() if val is not None else ""
            if "debug" in k and v in ("true", "1", "yes"):
                flags.append({"rule": "INSECURE_CONFIG", "key": key, "value": val,
                               "reason": "Debug mode enabled"})
            if any(s in k for s in ("password", "secret", "api_key", "token")) and len(str(val)) > 3:
                if not any(p in str(val) for p in ("${", "{{", "env(", "vault:")):
                    flags.append({"rule": "HARDCODED_SECRET", "key": key, "value": "***",
                                   "reason": f"Possible credential in config key '{key}'"})
            if "allow_origins" in k and "*" in str(val):
                flags.append({"rule": "MISCONFIGURED_CORS", "key": key, "value": val,
                               "reason": "CORS wildcard detected"})
        return flags

    def _flag_json(self, data: dict, path: str) -> list[dict]:
        flags = []
        flat  = _flatten(data)
        for key, val in flat.items():
            k = key.lower()
            if any(s in k for s in ("password", "secret", "key", "token")) and isinstance(val, str) and len(val) > 5:
                flags.append({"rule": "HARDCODED_SECRET", "key": key, "value": "***",
                               "reason": "Possible credential in JSON config"})
        return flags

    def _parse_dotenv(self, content: str) -> dict:
        result = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip().strip('"').strip("'")
        return result

    def _flag_env(self, data: dict, path: str) -> list[dict]:
        flags = []
        placeholder_patterns = {"your_key", "changeme", "xxxx", "placeholder", "todo", "example", "insert"}
        for key, val in data.items():
            k = key.lower()
            v = val.lower() if val else ""
            # Real secrets (not placeholders) hardcoded in .env committed to repo
            if any(s in k for s in ("secret", "password", "api_key", "token", "private")):
                if len(val) > 8 and not any(p in v for p in placeholder_patterns):
                    if ".env.example" not in path:
                        flags.append({"rule": "HARDCODED_SECRET", "key": key, "value": "***",
                                       "reason": f"Real credential may be committed in {path}"})
        return flags


# ─── Dependency Checker (Using pip-audit) ─────────────────────────────────────

import subprocess

class DependencyCheckerTool:
    """
    Wraps `pip-audit` to check requirements.txt for real vulnerabilities.
    Falls back to a basic package.json parser for JS (Node/npm audit can be added later).
    """

    def check_requirements_txt(self, content: str, file_path: str = "requirements.txt", repo_root: str = "") -> dict:
        """Runs pip-audit against the requirements.txt file."""
        start = time.time()
        flags = []
        
        # We need the absolute path to the requirements.txt to pass to pip-audit
        full_path = Path(repo_root) / file_path if repo_root else Path(file_path)
        
        if full_path.exists():
            try:
                # Run pip-audit and ask for JSON output
                result = subprocess.run(
                    ["pip-audit", "-r", str(full_path), "-f", "json"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                # pip-audit returns 0 if clean, non-zero if vulns found. 
                # Either way, stdout contains the JSON if -f json is used.
                if result.stdout.strip():
                    audit_data = json.loads(result.stdout)
                    for dep in audit_data.get("dependencies", []):
                        for vuln in dep.get("vulns", []):
                            flags.append({
                                "package": dep.get("name"),
                                "specified": dep.get("version"),
                                "cve": vuln.get("id"),
                                "severity": "high", # pip-audit doesn't always provide severity, defaulting to high
                                "rule_id": "VULNERABLE_DEPENDENCY",
                                "reason": vuln.get("fix_versions", ["No fix available"])[0] 
                                          if vuln.get("fix_versions") else vuln.get("description", "Vulnerability found"),
                                "description": vuln.get("description", "")
                            })
            except Exception as e:
                return {"file_path": file_path, "error": f"pip-audit failed: {str(e)}", "flag_count": 0}

        return {
            "file_path":    file_path,
            "flagged":      flags,
            "flag_count":   len(flags),
            "duration_ms":  int((time.time() - start) * 1000),
        }

    def check_package_json(self, content: str, file_path: str = "package.json") -> dict:
        # Placeholder for npm audit (Can be implemented similarly to pip-audit)
        start = time.time()
        return {
            "file_path":   file_path,
            "total_deps":  0,
            "flagged":     [],
            "flag_count":  0,
            "duration_ms": int((time.time() - start) * 1000),
            "note": "JS dependency scanning not yet integrated."
        }

    def format_for_prompt(self, result: dict) -> str:
        if not result.get("flagged"):
            return f"No known vulnerable dependencies found in {result.get('file_path', 'file')}."
        lines = [f"Dependency flags in {result.get('file_path', 'file')}:"]
        for f in result["flagged"]:
            lines.append(
                f"  - {f['package']} ({f['specified']}) → "
                f"Vulnerability: {f['cve']} | Fix/Reason: {f['reason']}\n"
                f"    Details: {f.get('description', '')[:200]}..."
            )
        return "\n".join(lines)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _flatten(d: Any, prefix: str = "") -> dict:
    """Recursively flatten nested dict to dot-notation keys."""
    items: dict = {}
    if isinstance(d, dict):
        for k, v in d.items():
            new_key = f"{prefix}.{k}" if prefix else k
            items.update(_flatten(v, new_key))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            items.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        items[prefix] = d
    return items

def _safe_truncate(obj: Any, max_chars: int = 3000) -> Any:
    """Truncate large parsed objects to avoid memory bloat."""
    s = json.dumps(obj, default=str)
    if len(s) <= max_chars:
        return obj
    return {"_truncated": True, "preview": s[:max_chars]}

