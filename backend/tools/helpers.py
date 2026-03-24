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


# ─── Dependency Checker ───────────────────────────────────────────────────────

# Known risky packages / version patterns (simplified — not a full CVE DB)
# In a real deployment Azure AI Search would back this with a full CVE index.
KNOWN_RISKY: dict[str, dict] = {
    "django":         {"min_safe": "4.2.0",  "cve": "CVE-2023-36053", "severity": "high"},
    "flask":          {"min_safe": "2.3.0",  "cve": "CVE-2023-30861", "severity": "high"},
    "requests":       {"min_safe": "2.31.0", "cve": "CVE-2023-32681", "severity": "medium"},
    "pillow":         {"min_safe": "10.0.0", "cve": "CVE-2023-44271", "severity": "high"},
    "cryptography":   {"min_safe": "41.0.0", "cve": "CVE-2023-49083", "severity": "high"},
    "pyyaml":         {"min_safe": "6.0",    "cve": "CVE-2022-1471",  "severity": "high"},
    "sqlalchemy":     {"min_safe": "2.0.0",  "cve": "CVE-2023-30560", "severity": "medium"},
    "paramiko":       {"min_safe": "3.4.0",  "cve": "CVE-2023-48795", "severity": "medium"},
    "aiohttp":        {"min_safe": "3.9.0",  "cve": "CVE-2023-49082", "severity": "high"},
    "werkzeug":       {"min_safe": "3.0.1",  "cve": "CVE-2023-46136", "severity": "high"},
    "lodash":         {"min_safe": "4.17.21","cve": "CVE-2021-23337", "severity": "high"},
    "axios":          {"min_safe": "1.6.0",  "cve": "CVE-2023-45857", "severity": "medium"},
    "jsonwebtoken":   {"min_safe": "9.0.0",  "cve": "CVE-2022-23529", "severity": "high"},
}


class DependencyCheckerTool:
    """
    Parses requirements.txt or package.json and checks for risky dependencies.
    Returns structured findings for AnalysisAgent to reason over.
    """

    def check_requirements_txt(self, content: str, file_path: str = "requirements.txt") -> dict:
        start = time.time()
        packages = self._parse_requirements(content)
        flags    = self._check_packages(packages)
        return {
            "file_path":    file_path,
            "total_deps":   len(packages),
            "flagged":      flags,
            "flag_count":   len(flags),
            "duration_ms":  int((time.time() - start) * 1000),
        }

    def check_package_json(self, content: str, file_path: str = "package.json") -> dict:
        start = time.time()
        try:
            data     = json.loads(content)
            packages = {}
            for section in ("dependencies", "devDependencies"):
                packages.update(data.get(section, {}))
            flags = self._check_packages(packages)
            return {
                "file_path":   file_path,
                "total_deps":  len(packages),
                "flagged":     flags,
                "flag_count":  len(flags),
                "duration_ms": int((time.time() - start) * 1000),
            }
        except Exception as e:
            return {"file_path": file_path, "error": str(e), "flag_count": 0}

    def _parse_requirements(self, content: str) -> dict[str, str]:
        packages = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle: package==1.0, package>=1.0, package~=1.0, package
            m = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([><=~!]+\s*[\d\.]+)?', line)
            if m:
                name    = m.group(1).lower()
                version = m.group(2).strip() if m.group(2) else "unspecified"
                packages[name] = version
        return packages

    def _check_packages(self, packages: dict[str, str]) -> list[dict]:
        flags = []
        for name, version_spec in packages.items():
            name_lower = name.lower().replace("-", "").replace("_", "")
            for risky_name, info in KNOWN_RISKY.items():
                risky_clean = risky_name.replace("-", "").replace("_", "")
                if name_lower == risky_clean:
                    flags.append({
                        "package":    name,
                        "specified":  version_spec,
                        "min_safe":   info["min_safe"],
                        "cve":        info["cve"],
                        "severity":   info["severity"],
                        "rule_id":    "VULNERABLE_DEPENDENCY",
                        "reason":     f"{name} {version_spec} may be below safe version {info['min_safe']} ({info['cve']})",
                    })
        return flags

    def format_for_prompt(self, result: dict) -> str:
        if not result.get("flagged"):
            return f"No known vulnerable dependencies found in {result.get('file_path', 'file')}."
        lines = [f"Dependency flags in {result.get('file_path', 'file')}:"]
        for f in result["flagged"]:
            lines.append(
                f"  - {f['package']} (specified: {f['specified']}) → "
                f"{f['cve']} | severity: {f['severity']} | "
                f"min safe: {f['min_safe']}"
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
