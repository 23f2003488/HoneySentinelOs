"""
Tests for all tools (file_scanner, pattern_detector, yaml_parser, dependency_checker).
No Azure OpenAI needed — tools are deterministic.
Run: python tests/test_tools.py
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Bootstrap policy so tools can call get_policy_engine()
from backend.policy import get_policy_engine, reset_policy_engine
POLICY_PATH = Path(__file__).parent.parent / "config" / "security_policy.yaml"
reset_policy_engine()
get_policy_engine(POLICY_PATH)

from backend.tools import (
    FileScannerTool, PatternDetectorTool,
    YamlParserTool, DependencyCheckerTool,
)

passed = 0
failed = 0


def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  PASS  {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL  {name}: {e}")
        import traceback; traceback.print_exc()
        failed += 1


# ── FileScannerTool ────────────────────────────────────────────────────────────

def test_scan_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        result = FileScannerTool().scan_directory(d)
        assert result["total_files"] == 0

def test_scan_finds_python_files():
    with tempfile.TemporaryDirectory() as d:
        Path(d, "app.py").write_text("print('hello')")
        Path(d, "utils.py").write_text("x = 1")
        result = FileScannerTool().scan_directory(d)
        assert result["total_files"] == 2
        assert "python" in result["languages_detected"]

def test_scan_excludes_node_modules():
    with tempfile.TemporaryDirectory() as d:
        nm = Path(d, "node_modules"); nm.mkdir()
        Path(nm, "index.js").write_text("module.exports = {}")
        Path(d, "app.py").write_text("x=1")
        result = FileScannerTool().scan_directory(d)
        # Only app.py should be found
        paths = [f["path"] for f in result["files"]]
        assert not any("node_modules" in p for p in paths)

def test_scan_detects_entry_points():
    with tempfile.TemporaryDirectory() as d:
        Path(d, "main.py").write_text("if __name__=='__main__': pass")
        result = FileScannerTool().scan_directory(d)
        assert "main.py" in result["entry_points"]

def test_scan_detects_config_files():
    with tempfile.TemporaryDirectory() as d:
        Path(d, "config.yaml").write_text("debug: false")
        result = FileScannerTool().scan_directory(d)
        assert "config.yaml" in result["config_files"]

def test_read_file_content_returns_content():
    with tempfile.TemporaryDirectory() as d:
        Path(d, "app.py").write_text("SECRET_KEY = 'abc123'\n")
        result = FileScannerTool().read_file_content(d, "app.py")
        assert "SECRET_KEY" in result["content"]
        assert result["lines"] >= 1

def test_read_nonexistent_file_returns_error():
    with tempfile.TemporaryDirectory() as d:
        result = FileScannerTool().read_file_content(d, "ghost.py")
        assert "error" in result

def test_nonexistent_dir_returns_error():
    result = FileScannerTool().scan_directory("/nonexistent/path/xyz")
    assert "error" in result


# ── PatternDetectorTool ────────────────────────────────────────────────────────

def test_detects_hardcoded_password():
    tool    = PatternDetectorTool()
    content = 'DB_PASSWORD = "supersecret123"\n'
    result  = tool.scan_content("app.py", content, "python")
    assert result.has_matches()
    rule_ids = [m.rule_id for m in result.matches]
    assert "HARDCODED_SECRET" in rule_ids

def test_detects_sql_injection():
    tool    = PatternDetectorTool()
    content = 'query = f"SELECT * FROM users WHERE id = {user_id}"\n'
    result  = tool.scan_content("db.py", content, "python")
    assert result.has_matches()
    rule_ids = [m.rule_id for m in result.matches]
    assert "SQL_INJECTION" in rule_ids

def test_detects_pickle_loads():
    tool    = PatternDetectorTool()
    content = "import pickle\ndata = pickle.loads(user_input)\n"
    result  = tool.scan_content("utils.py", content, "python")
    assert result.has_matches()
    rule_ids = [m.rule_id for m in result.matches]
    assert "INSECURE_DESERIALIZATION" in rule_ids

def test_detects_cors_wildcard():
    tool    = PatternDetectorTool()
    content = 'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
    result  = tool.scan_content("main.py", content, "python")
    assert result.has_matches()

def test_clean_file_no_matches():
    tool    = PatternDetectorTool()
    content = "def add(a, b):\n    return a + b\n"
    result  = tool.scan_content("math.py", content, "python")
    assert not result.has_matches()

def test_false_positive_suppressed():
    tool    = PatternDetectorTool()
    # "test fixture" in line should suppress the match
    content = 'SECRET = "abc123"  # test fixture placeholder\n'
    result  = tool.scan_content("tests/fixtures.py", content, "python")
    # Should be suppressed — line contains "test fixture"
    secret_matches = [m for m in result.matches if m.rule_id == "HARDCODED_SECRET"]
    assert len(secret_matches) == 0

def test_match_includes_context_lines():
    tool    = PatternDetectorTool()
    content = "x = 1\ny = 2\nSECRET = 'real_secret_here'\nz = 3\n"
    result  = tool.scan_content("app.py", content, "python")
    if result.matches:
        assert len(result.matches[0].context_lines) > 0

def test_format_for_prompt_no_matches():
    tool    = PatternDetectorTool()
    result  = tool.scan_content("empty.py", "x = 1", "python")
    formatted = tool.format_matches_for_prompt(result)
    assert "No pattern matches" in formatted

def test_format_for_prompt_with_matches():
    tool    = PatternDetectorTool()
    content = 'PASSWORD = "mysecret"\n'
    result  = tool.scan_content("app.py", content, "python")
    formatted = tool.format_matches_for_prompt(result)
    assert "app.py" in formatted


# ── YamlParserTool ─────────────────────────────────────────────────────────────

def test_yaml_parser_debug_flag():
    tool   = YamlParserTool()
    result = tool.parse_file("config.yaml", "debug: true\napp:\n  name: myapp\n")
    assert result["parse_ok"]
    flags = result["security_flags"]
    assert any(f["rule"] == "INSECURE_CONFIG" for f in flags)

def test_yaml_parser_no_flags_clean():
    tool   = YamlParserTool()
    result = tool.parse_file("config.yaml", "app:\n  name: myapp\n  port: 8080\n")
    assert result["parse_ok"]
    assert len(result["security_flags"]) == 0

def test_yaml_parser_cors_wildcard():
    tool   = YamlParserTool()
    yaml_content = "cors:\n  allow_origins: \"*\"\n"
    result = tool.parse_file("settings.yaml", yaml_content)
    flags = result["security_flags"]
    assert any(f["rule"] == "MISCONFIGURED_CORS" for f in flags)

def test_dotenv_parser_flags_real_secret():
    tool   = YamlParserTool()
    result = tool.parse_file(".env", "DJANGO_SECRET_KEY=actualrealkey12345\nDEBUG=False\n")
    flags  = result["security_flags"]
    assert any(f["rule"] == "HARDCODED_SECRET" for f in flags)

def test_dotenv_example_not_flagged():
    tool   = YamlParserTool()
    # .env.example should not trigger
    result = tool.parse_file(".env.example", "API_KEY=your_api_key_here\n")
    flags  = result["security_flags"]
    secret_flags = [f for f in flags if f["rule"] == "HARDCODED_SECRET"]
    assert len(secret_flags) == 0

def test_invalid_yaml_returns_error():
    tool   = YamlParserTool()
    result = tool.parse_file("bad.yaml", "{{invalid: yaml: content: [}")
    assert not result["parse_ok"] or "error" in result


# ── DependencyCheckerTool ──────────────────────────────────────────────────────

def test_requirements_flags_vulnerable():
    tool    = DependencyCheckerTool()
    content = "django==3.2.0\nrequests==2.20.0\nflask==1.0.0\n"
    result  = tool.check_requirements_txt(content)
    assert result["flag_count"] > 0
    rules = [f["rule_id"] for f in result["flagged"]]
    assert "VULNERABLE_DEPENDENCY" in rules

def test_requirements_safe_versions():
    tool    = DependencyCheckerTool()
    # Use very new versions unlikely to be flagged
    content = "django==5.0.0\nrequests==2.32.0\n"
    result  = tool.check_requirements_txt(content)
    # django 5.0.0 > 4.2.0 min safe, requests 2.32.0 > 2.31.0
    assert result["flag_count"] == 0

def test_requirements_no_version_still_checked():
    tool    = DependencyCheckerTool()
    content = "django\npillow\n"
    result  = tool.check_requirements_txt(content)
    # unspecified version → should still be flagged
    assert result["flag_count"] > 0

def test_package_json_flags_vulnerable():
    tool    = DependencyCheckerTool()
    content = '{"dependencies": {"axios": "0.21.0", "lodash": "4.16.0"}}'
    result  = tool.check_package_json(content)
    assert result["flag_count"] > 0

def test_package_json_invalid_json():
    tool   = DependencyCheckerTool()
    result = tool.check_package_json("{not valid json}")
    assert "error" in result

def test_format_for_prompt_no_flags():
    tool    = DependencyCheckerTool()
    result  = {"flagged": [], "file_path": "requirements.txt", "flag_count": 0}
    output  = tool.format_for_prompt(result)
    assert "No known vulnerable" in output

def test_format_for_prompt_with_flags():
    tool    = DependencyCheckerTool()
    content = "pyyaml==5.3\n"
    result  = tool.check_requirements_txt(content)
    output  = tool.format_for_prompt(result)
    assert "pyyaml" in output.lower() or "CVE" in output


# ── Runner ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    all_tests = [
        # FileScannerTool
        ("scanner_empty_dir",                  test_scan_empty_dir),
        ("scanner_finds_python",               test_scan_finds_python_files),
        ("scanner_excludes_node_modules",      test_scan_excludes_node_modules),
        ("scanner_detects_entry_points",       test_scan_detects_entry_points),
        ("scanner_detects_config_files",       test_scan_detects_config_files),
        ("scanner_read_file_content",          test_read_file_content_returns_content),
        ("scanner_read_nonexistent_error",     test_read_nonexistent_file_returns_error),
        ("scanner_nonexistent_dir_error",      test_nonexistent_dir_returns_error),
        # PatternDetectorTool
        ("pattern_hardcoded_password",         test_detects_hardcoded_password),
        ("pattern_sql_injection",              test_detects_sql_injection),
        ("pattern_pickle_loads",               test_detects_pickle_loads),
        ("pattern_cors_wildcard",              test_detects_cors_wildcard),
        ("pattern_clean_file",                 test_clean_file_no_matches),
        ("pattern_fp_suppressed",              test_false_positive_suppressed),
        ("pattern_context_lines",              test_match_includes_context_lines),
        ("pattern_format_no_matches",          test_format_for_prompt_no_matches),
        ("pattern_format_with_matches",        test_format_for_prompt_with_matches),
        # YamlParserTool
        ("yaml_debug_flag",                    test_yaml_parser_debug_flag),
        ("yaml_clean_no_flags",                test_yaml_parser_no_flags_clean),
        ("yaml_cors_wildcard",                 test_yaml_parser_cors_wildcard),
        ("env_real_secret_flagged",            test_dotenv_parser_flags_real_secret),
        ("env_example_not_flagged",            test_dotenv_example_not_flagged),
        ("yaml_invalid_handled",               test_invalid_yaml_returns_error),
        # DependencyCheckerTool
        ("dep_requirements_vulnerable",        test_requirements_flags_vulnerable),
        ("dep_requirements_safe",              test_requirements_safe_versions),
        ("dep_requirements_no_version",        test_requirements_no_version_still_checked),
        ("dep_package_json_vulnerable",        test_package_json_flags_vulnerable),
        ("dep_package_json_invalid",           test_package_json_invalid_json),
        ("dep_format_no_flags",                test_format_for_prompt_no_flags),
        ("dep_format_with_flags",              test_format_for_prompt_with_flags),
    ]

    print(f"\nRunning {len(all_tests)} tool tests...\n")
    for name, fn in all_tests:
        test(name, fn)

    print(f"\n{'='*40}")
    print(f"  {passed} passed, {failed} failed")
    print(f"{'='*40}\n")
