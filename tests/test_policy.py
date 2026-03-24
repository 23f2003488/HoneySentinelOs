"""
Tests for PolicyEngine.
Run: python tests/test_policy.py
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.policy import (
    get_policy_engine, reset_policy_engine,
    PolicyEngine, PolicyLoadError,
)

POLICY_PATH = Path(__file__).parent.parent / "config" / "security_policy.yaml"

passed = 0
failed = 0


def test(name: str, fn):
    global passed, failed
    reset_policy_engine()
    try:
        fn()
        print(f"  PASS  {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL  {name}: {e}")
        import traceback; traceback.print_exc()
        failed += 1
    finally:
        reset_policy_engine()


# ─── Load tests ───────────────────────────────────────────────────────────────

def test_loads_successfully():
    engine = get_policy_engine(POLICY_PATH)
    assert engine._loaded
    assert engine.version == "1.0"

def test_missing_file_raises():
    try:
        PolicyEngine(Path("/nonexistent/policy.yaml")).load()
        assert False, "Should have raised"
    except PolicyLoadError as e:
        assert "not found" in str(e)

def test_singleton_returns_same_instance():
    e1 = get_policy_engine(POLICY_PATH)
    e2 = get_policy_engine(POLICY_PATH)
    assert e1 is e2


# ─── Context tests ────────────────────────────────────────────────────────────

def test_context_parsed_correctly():
    engine = get_policy_engine(POLICY_PATH)
    ctx = engine.context
    assert ctx.project_type == "web_application"
    assert ctx.authentication_type == "jwt"
    assert ctx.data_sensitivity == "high"
    assert ctx.handles_pii is True
    assert "python" in ctx.language_stack

def test_context_prompt_block_contains_key_fields():
    engine = get_policy_engine(POLICY_PATH)
    block = engine.get_context_prompt()
    assert "TARGET SYSTEM CONTEXT" in block
    assert "jwt" in block
    assert "HIGH" in block
    assert "PII" in block.upper() or "pii" in block.lower()


# ─── Rules tests ──────────────────────────────────────────────────────────────

def test_all_enabled_rules_loaded():
    engine = get_policy_engine(POLICY_PATH)
    assert len(engine.rules) >= 8  # we defined 10 in yaml

def test_get_rule_by_id():
    engine = get_policy_engine(POLICY_PATH)
    rule = engine.get_rule("HARDCODED_SECRET")
    assert rule is not None
    assert rule.severity == "critical"
    assert len(rule.pattern_hints) > 0
    assert len(rule.false_positive_signals) > 0

def test_get_rule_nonexistent_returns_none():
    engine = get_policy_engine(POLICY_PATH)
    assert engine.get_rule("DOES_NOT_EXIST") is None

def test_get_enabled_rules_language_filter():
    engine = get_policy_engine(POLICY_PATH)
    python_rules = engine.get_enabled_rules(language="python")
    assert len(python_rules) > 0
    # INSECURE_DESERIALIZATION is python-only
    rule_ids = [r.id for r in python_rules]
    assert "INSECURE_DESERIALIZATION" in rule_ids

def test_get_rules_for_prompt_is_string():
    engine = get_policy_engine(POLICY_PATH)
    prompt = engine.get_rules_for_prompt(language="python")
    assert isinstance(prompt, str)
    assert "ACTIVE SECURITY RULES" in prompt
    assert "HARDCODED_SECRET" in prompt

def test_rule_prompt_block_format():
    engine = get_policy_engine(POLICY_PATH)
    rule = engine.get_rule("SQL_INJECTION")
    block = rule.to_prompt_block()
    assert "SQL_INJECTION" in block
    assert "severity" in block
    assert "False positive" in block


# ─── Agent config tests ───────────────────────────────────────────────────────

def test_agent_config_parsed():
    engine = get_policy_engine(POLICY_PATH)
    cfg = engine.get_agent_config()
    assert 0.0 < cfg.confidence_threshold < 1.0
    assert cfg.max_iterations > 0
    assert cfg.max_findings > 0

def test_should_ask_human_below_threshold():
    engine = get_policy_engine(POLICY_PATH)
    threshold = engine.agent_config.confidence_threshold
    assert engine.should_ask_human(threshold - 0.01) is True

def test_should_not_ask_human_above_threshold():
    engine = get_policy_engine(POLICY_PATH)
    threshold = engine.agent_config.confidence_threshold
    assert engine.should_ask_human(threshold + 0.01) is False

def test_should_ask_human_at_exact_threshold():
    engine = get_policy_engine(POLICY_PATH)
    threshold = engine.agent_config.confidence_threshold
    # At exactly threshold — not triggered (must be strictly below)
    assert engine.should_ask_human(threshold) is False


# ─── Scope tests ──────────────────────────────────────────────────────────────

def test_python_file_in_scope():
    engine = get_policy_engine(POLICY_PATH)
    assert engine.is_in_scope("app.py") is True

def test_yaml_file_in_scope():
    engine = get_policy_engine(POLICY_PATH)
    assert engine.is_in_scope("config.yaml") is True

def test_node_modules_excluded():
    engine = get_policy_engine(POLICY_PATH)
    assert engine.is_in_scope("node_modules/lodash/index.js") is False

def test_git_directory_excluded():
    engine = get_policy_engine(POLICY_PATH)
    assert engine.is_in_scope(".git/config") is False

def test_minified_js_excluded():
    engine = get_policy_engine(POLICY_PATH)
    assert engine.is_in_scope("dist/bundle.min.js") is False

def test_unknown_extension_excluded():
    engine = get_policy_engine(POLICY_PATH)
    assert engine.is_in_scope("readme.md") is False

def test_file_too_large_excluded():
    engine = get_policy_engine(POLICY_PATH)
    max_bytes = engine.scope.max_file_size_kb * 1024
    assert engine.is_in_scope("app.py", file_size_bytes=max_bytes + 1) is False

def test_file_within_size_limit_included():
    engine = get_policy_engine(POLICY_PATH)
    assert engine.is_in_scope("app.py", file_size_bytes=1024) is True


# ─── Severity action tests ────────────────────────────────────────────────────

def test_severity_action_critical():
    engine = get_policy_engine(POLICY_PATH)
    action = engine.get_severity_action("critical")
    assert action is not None
    assert action.escalate is True
    assert "immediately" in action.recommended_action.lower()

def test_severity_action_low():
    engine = get_policy_engine(POLICY_PATH)
    action = engine.get_severity_action("low")
    assert action.escalate is False

def test_severity_action_unknown_returns_none():
    engine = get_policy_engine(POLICY_PATH)
    assert engine.get_severity_action("nonexistent") is None


# ─── Summary test ─────────────────────────────────────────────────────────────

def test_summary_has_required_keys():
    engine = get_policy_engine(POLICY_PATH)
    summary = engine.summary()
    for key in ["version", "project", "data_sensitivity", "rules_enabled", "confidence_threshold"]:
        assert key in summary, f"Missing key: {key}"
    assert summary["rules_enabled"] >= 8


# ─── Not-loaded guard test ────────────────────────────────────────────────────

def test_unloaded_engine_raises():
    engine = PolicyEngine(POLICY_PATH)   # not calling .load()
    try:
        engine.get_context_prompt()
        assert False, "Should have raised"
    except RuntimeError as e:
        assert "not loaded" in str(e)


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        ("loads_successfully",                test_loads_successfully),
        ("missing_file_raises",               test_missing_file_raises),
        ("singleton_returns_same_instance",   test_singleton_returns_same_instance),
        ("context_parsed_correctly",          test_context_parsed_correctly),
        ("context_prompt_block_fields",       test_context_prompt_block_contains_key_fields),
        ("all_enabled_rules_loaded",          test_all_enabled_rules_loaded),
        ("get_rule_by_id",                    test_get_rule_by_id),
        ("get_rule_nonexistent_none",         test_get_rule_nonexistent_returns_none),
        ("rules_language_filter",             test_get_enabled_rules_language_filter),
        ("rules_for_prompt_string",           test_get_rules_for_prompt_is_string),
        ("rule_prompt_block_format",          test_rule_prompt_block_format),
        ("agent_config_parsed",               test_agent_config_parsed),
        ("should_ask_human_below",            test_should_ask_human_below_threshold),
        ("should_not_ask_human_above",        test_should_not_ask_human_above_threshold),
        ("should_ask_human_at_threshold",     test_should_ask_human_at_exact_threshold),
        ("python_file_in_scope",             test_python_file_in_scope),
        ("yaml_file_in_scope",               test_yaml_file_in_scope),
        ("node_modules_excluded",            test_node_modules_excluded),
        ("git_dir_excluded",                 test_git_directory_excluded),
        ("minified_js_excluded",             test_minified_js_excluded),
        ("unknown_extension_excluded",       test_unknown_extension_excluded),
        ("file_too_large_excluded",          test_file_too_large_excluded),
        ("file_within_size_included",        test_file_within_size_limit_included),
        ("severity_action_critical",         test_severity_action_critical),
        ("severity_action_low",              test_severity_action_low),
        ("severity_action_unknown_none",     test_severity_action_unknown_returns_none),
        ("summary_required_keys",            test_summary_has_required_keys),
        ("unloaded_engine_raises",           test_unloaded_engine_raises),
    ]

    print(f"\nRunning {len(tests)} policy engine tests...\n")
    for name, fn in tests:
        test(name, fn)

    print(f"\n{'='*40}")
    print(f"  {passed} passed, {failed} failed")
    print(f"{'='*40}\n")
