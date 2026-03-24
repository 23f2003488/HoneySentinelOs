"""
HoneySentinel-OS — FastAPI Application
REST endpoints + WebSocket for live agent streaming.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()

from backend.memory import get_memory_store, SessionStatus
from backend.policy import get_policy_engine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

POLICY_PATH = Path(os.getenv("POLICY_PATH", "config/security_policy.yaml"))

# Always use the real system temp dir — never trust UPLOAD_DIR env on Windows
UPLOAD_DIR = Path(tempfile.gettempdir()) / "honeySentinel_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
logger.info(f"Upload dir: {UPLOAD_DIR}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_policy_engine(POLICY_PATH)
    logger.info("HoneySentinel-OS API ready")
    yield


app = FastAPI(title="HoneySentinel-OS", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectionManager:
    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, session_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.setdefault(session_id, []).append(ws)

    def disconnect(self, session_id: str, ws: WebSocket) -> None:
        conns = self._connections.get(session_id, [])
        if ws in conns:
            conns.remove(ws)

    async def broadcast(self, session_id: str, data: dict) -> None:
        conns = self._connections.get(session_id, [])
        dead = []
        for ws in conns:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            conns.remove(ws)


manager = ConnectionManager()


def _make_change_handler(session_id: str):
    async def handler(event):
        await manager.broadcast(session_id, {
            "type":      "agent_update",
            "namespace": event.namespace,
            "key":       event.key,
            "data":      event.data,
            "timestamp": event.timestamp,
        })
    return handler


class AnalyseRepoRequest(BaseModel):
    repo_path: str
    session_id: Optional[str] = None

class AnalyseGithubRequest(BaseModel):
    github_url: str
    session_id: Optional[str] = None

class AnswerRequest(BaseModel):
    answer: str


@app.get("/health")
async def health():
    policy = get_policy_engine()
    return {"status": "ok", "policy": policy.summary(), "version": "1.0.0",
            "upload_dir": str(UPLOAD_DIR)}


@app.post("/analyse/repo")
async def analyse_repo(request: AnalyseRepoRequest):
    session_id = request.session_id or str(uuid.uuid4())[:12]
    repo_path  = request.repo_path
    if not Path(repo_path).exists():
        raise HTTPException(status_code=400, detail=f"Path not found: {repo_path}")
    memory = get_memory_store()
    memory.subscribe(_make_change_handler(session_id))
    asyncio.create_task(_run_analysis(session_id, repo_path))
    return {"session_id": session_id, "status": "started", "ws_url": f"/ws/{session_id}"}


@app.post("/analyse/upload")
async def analyse_upload(file: UploadFile = File(...)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported.")
    session_id = str(uuid.uuid4())[:12]
    dest = UPLOAD_DIR / f"{session_id}_{file.filename}"
    contents = await file.read()
    dest.write_bytes(contents)
    memory = get_memory_store()
    memory.subscribe(_make_change_handler(session_id))
    asyncio.create_task(_run_analysis(session_id, str(dest)))
    return {"session_id": session_id, "status": "started",
            "filename": file.filename, "ws_url": f"/ws/{session_id}"}


@app.post("/analyse/github")
async def analyse_github(request: AnalyseGithubRequest):
    session_id = str(uuid.uuid4())[:12]
    github_url = request.github_url.strip()

    if not github_url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    if not shutil.which("git"):
        raise HTTPException(status_code=500, detail="git is not installed on the server.")

    # Always use resolved absolute path — critical on Windows
    clone_dir = (UPLOAD_DIR / f"{session_id}_repo").resolve()
    if clone_dir.exists():
        shutil.rmtree(clone_dir, ignore_errors=True)

    logger.info(f"Cloning {github_url} into {clone_dir}")

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", github_url, str(clone_dir)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            err = result.stderr.strip()
            logger.error(f"Git clone failed: {err}")
            raise HTTPException(status_code=400, detail=f"Git clone failed: {err[:400]}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Git clone timed out after 120s.")

    memory = get_memory_store()
    memory.subscribe(_make_change_handler(session_id))
    asyncio.create_task(_run_analysis(session_id, str(clone_dir)))

    return {
        "session_id": session_id,
        "status":     "started",
        "repo_url":   github_url,
        "clone_dir":  str(clone_dir),
        "ws_url":     f"/ws/{session_id}",
    }


@app.get("/session/{session_id}")
async def get_session(session_id: str):
    memory = get_memory_store()
    snap   = await memory.snapshot(session_id)
    if not snap["session"]:
        raise HTTPException(status_code=404, detail="Session not found")
    return snap


@app.get("/session/{session_id}/findings")
async def get_findings(session_id: str):
    memory   = get_memory_store()
    findings = await memory.get_findings(session_id)
    return {"session_id": session_id, "findings": [f.to_dict() for f in findings]}


@app.get("/session/{session_id}/agents")
async def get_agents(session_id: str):
    memory = get_memory_store()
    states = await memory.get_all_agent_states(session_id)
    return {"session_id": session_id, "agents": [s.to_dict() for s in states]}


@app.get("/session/{session_id}/hitl")
async def get_hitl_questions(session_id: str):
    memory  = get_memory_store()
    pending = await memory.get_pending_questions(session_id)
    return {"session_id": session_id, "pending": [q.to_dict() for q in pending], "count": len(pending)}


@app.post("/session/{session_id}/hitl/{question_id}/answer")
async def answer_hitl(session_id: str, question_id: str, body: AnswerRequest):
    memory = get_memory_store()
    q      = await memory.get_question(session_id, question_id)
    if not q:
        raise HTTPException(status_code=404, detail="Question not found")
    if q.answer:
        raise HTTPException(status_code=400, detail="Already answered")
    await memory.answer_question(session_id, question_id, body.answer)
    await manager.broadcast(session_id, {
        "type": "hitl_answered", "question_id": question_id, "answer": body.answer,
    })
    return {"status": "answered", "question_id": question_id}


@app.get("/session/{session_id}/report")
async def get_report(session_id: str):
    memory = get_memory_store()
    sess   = await memory.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess.status != SessionStatus.DONE:
        return {"status": sess.status.value, "message": "Analysis still in progress."}
    results = await memory.get_tool_results(session_id, agent_id="report-001")
    if not results:
        raise HTTPException(status_code=404, detail="Report not yet generated")
    return results[-1].output


@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await manager.connect(session_id, websocket)
    memory = get_memory_store()
    snap   = await memory.snapshot(session_id)
    await websocket.send_text(json.dumps({"type": "snapshot", "data": snap}))
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        manager.disconnect(session_id, websocket)


async def _run_analysis(session_id: str, path: str) -> None:
    from backend.agents.orchestrator import OrchestratorAgent
    try:
        orch = OrchestratorAgent(session_id=session_id, repo_path=path)
        await orch.run()
        await manager.broadcast(session_id, {"type": "analysis_complete", "session": session_id})
    except Exception as e:
        logger.exception(f"[{session_id}] Analysis failed")
        await manager.broadcast(session_id, {"type": "error", "error": str(e)})