"""
Tests for LocalMemoryStore.
Run: python -m pytest tests/test_memory.py -v
"""

import asyncio
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.memory import (
    get_memory_store, reset_store, LocalMemoryStore,
    AgentState, AgentStatus, Finding, HITLQuestion, HITLStatus,
    RepoMap, FileNode, SessionMeta, SessionStatus, ToolResult, Severity,
)


@pytest.fixture(autouse=True)
def fresh_store():
    reset_store()
    yield
    reset_store()


@pytest.fixture
def store() -> LocalMemoryStore:
    return get_memory_store()


@pytest.fixture
def session_id() -> str:
    return "test-session-001"


@pytest.fixture
def sample_session(session_id) -> SessionMeta:
    return SessionMeta(
        session_id=session_id,
        status=SessionStatus.INITIALIZING,
        input_source="blob://repos/test-repo.zip",
        input_type="git_repo",
        policy_version="1.0",
    )


# ─── Session tests ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_and_get_session(store, sample_session, session_id):
    await store.create_session(sample_session)
    fetched = await store.get_session(session_id)
    assert fetched is not None
    assert fetched.session_id == session_id
    assert fetched.status == SessionStatus.INITIALIZING


@pytest.mark.asyncio
async def test_update_session(store, sample_session, session_id):
    await store.create_session(sample_session)
    await store.update_session(session_id, status=SessionStatus.RUNNING)
    fetched = await store.get_session(session_id)
    assert fetched.status == SessionStatus.RUNNING
    assert fetched.updated_at is not None


@pytest.mark.asyncio
async def test_get_nonexistent_session(store):
    result = await store.get_session("ghost-session")
    assert result is None


# ─── Repo map tests ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_and_get_repo_map(store, sample_session, session_id):
    await store.create_session(sample_session)
    repo_map = RepoMap(
        root_path="/tmp/test-repo",
        files=[
            FileNode(path="app.py", file_type="python", size_bytes=2048),
            FileNode(path="config.yaml", file_type="yaml", size_bytes=512),
        ],
        total_files=2,
        languages_detected=["python"],
        config_files=["config.yaml"],
    )
    await store.set_repo_map(session_id, repo_map)
    fetched = await store.get_repo_map(session_id)
    assert fetched is not None
    assert fetched.total_files == 2
    assert len(fetched.files) == 2
    assert fetched.files[0].path == "app.py"


# ─── Agent state tests ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_upsert_and_get_agent_state(store, sample_session, session_id):
    await store.create_session(sample_session)
    state = AgentState(
        agent_id="recon-001",
        agent_type="recon",
        goal="Map all files in the repository",
        status=AgentStatus.RUNNING,
    )
    await store.upsert_agent_state(session_id, state)
    fetched = await store.get_agent_state(session_id, "recon-001")
    assert fetched is not None
    assert fetched.goal == "Map all files in the repository"
    assert fetched.status == AgentStatus.RUNNING


@pytest.mark.asyncio
async def test_agent_state_update_increments_iterations(store, sample_session, session_id):
    await store.create_session(sample_session)
    state = AgentState(agent_id="analysis-001", agent_type="analysis", goal="Find vulns")
    await store.upsert_agent_state(session_id, state)

    state.update(
        thought="Scanning app.py for hardcoded secrets",
        last_action="pattern_detector(app.py)",
        last_observation="Found 1 potential secret on line 42",
        decision="continue",
        confidence=0.85,
    )
    await store.upsert_agent_state(session_id, state)

    fetched = await store.get_agent_state(session_id, "analysis-001")
    assert fetched.iterations == 1
    assert fetched.confidence == 0.85
    assert "secret" in fetched.last_observation


@pytest.mark.asyncio
async def test_get_all_agent_states(store, sample_session, session_id):
    await store.create_session(sample_session)
    for agent_id, agent_type in [("recon-001", "recon"), ("analysis-001", "analysis")]:
        state = AgentState(agent_id=agent_id, agent_type=agent_type, goal="test goal")
        await store.upsert_agent_state(session_id, state)

    all_states = await store.get_all_agent_states(session_id)
    assert len(all_states) == 2


# ─── Finding tests ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_add_and_get_findings(store, sample_session, session_id):
    await store.create_session(sample_session)
    finding = Finding(
        agent_id="analysis-001",
        file_path="app.py",
        rule_id="HARDCODED_SECRET",
        severity=Severity.CRITICAL,
        title="Hardcoded API key detected",
        description="API key found in plain text",
        evidence='SECRET_KEY = "abc123secret"',
        recommendation="Move to environment variable or Azure Key Vault",
        confidence=0.95,
    )
    await store.add_finding(session_id, finding)
    findings = await store.get_findings(session_id)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].confidence == 0.95


@pytest.mark.asyncio
async def test_multiple_findings_accumulate(store, sample_session, session_id):
    await store.create_session(sample_session)
    for i in range(3):
        f = Finding(agent_id="analysis-001", file_path=f"file_{i}.py",
                    rule_id="SQL_INJECTION", severity=Severity.HIGH,
                    title=f"SQL injection risk #{i}")
        await store.add_finding(session_id, f)

    findings = await store.get_findings(session_id)
    assert len(findings) == 3


# ─── HITL tests ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_push_and_answer_question(store, sample_session, session_id):
    await store.create_session(sample_session)
    question = HITLQuestion(
        agent_id="analysis-001",
        question="This pattern could be a false positive. Is this file intentionally test data?",
        context="Found string resembling a private key in tests/fixtures/mock_data.py",
        options=["Yes, it's test data — skip it", "No, treat it as real — flag it"],
    )
    await store.push_question(session_id, question)

    pending = await store.get_pending_questions(session_id)
    assert len(pending) == 1
    assert pending[0].status == HITLStatus.PENDING

    await store.answer_question(session_id, question.question_id, "Yes, it's test data — skip it")

    answered = await store.get_question(session_id, question.question_id)
    assert answered.status == HITLStatus.ANSWERED
    assert answered.answer == "Yes, it's test data — skip it"
    assert answered.answered_at is not None


@pytest.mark.asyncio
async def test_pending_questions_excludes_answered(store, sample_session, session_id):
    await store.create_session(sample_session)
    q1 = HITLQuestion(agent_id="a1", question="Question 1?")
    q2 = HITLQuestion(agent_id="a1", question="Question 2?")
    await store.push_question(session_id, q1)
    await store.push_question(session_id, q2)
    await store.answer_question(session_id, q1.question_id, "answer")

    pending = await store.get_pending_questions(session_id)
    assert len(pending) == 1
    assert pending[0].question_id == q2.question_id


# ─── Tool result tests ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_and_retrieve_tool_results(store, sample_session, session_id):
    await store.create_session(sample_session)
    result = ToolResult(
        tool_name="file_scanner",
        agent_id="recon-001",
        input_summary="Scanning /tmp/test-repo",
        output={"files_found": 42},
        success=True,
        duration_ms=120,
    )
    await store.log_tool_result(session_id, result)
    results = await store.get_tool_results(session_id)
    assert len(results) == 1
    assert results[0].tool_name == "file_scanner"


@pytest.mark.asyncio
async def test_tool_results_filter_by_agent(store, sample_session, session_id):
    await store.create_session(sample_session)
    for agent_id in ["recon-001", "recon-001", "analysis-001"]:
        r = ToolResult(tool_name="file_scanner", agent_id=agent_id, input_summary="x")
        await store.log_tool_result(session_id, r)

    recon_results = await store.get_tool_results(session_id, agent_id="recon-001")
    assert len(recon_results) == 2


# ─── Snapshot test ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_snapshot_contains_all_namespaces(store, sample_session, session_id):
    await store.create_session(sample_session)
    await store.upsert_agent_state(session_id, AgentState(
        agent_id="recon-001", agent_type="recon", goal="Map files"))
    await store.add_finding(session_id, Finding(
        agent_id="analysis-001", file_path="app.py",
        rule_id="TEST", severity=Severity.LOW, title="Test finding"))

    snap = await store.snapshot(session_id)
    assert snap["session"]["session_id"] == session_id
    assert len(snap["agent_states"]) == 1
    assert len(snap["findings"]) == 1
    assert "repo_map" in snap
    assert "hitl" in snap


# ─── Change event / subscription test ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_change_events_emitted_to_subscribers(store, sample_session, session_id):
    events = []
    store.subscribe(lambda e: events.append(e))

    await store.create_session(sample_session)
    state = AgentState(agent_id="recon-001", agent_type="recon", goal="test")
    await store.upsert_agent_state(session_id, state)

    assert len(events) >= 2
    namespaces = [e.namespace for e in events]
    assert "session" in namespaces
    assert "agent_state" in namespaces
