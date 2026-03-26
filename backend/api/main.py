"""
HoneySentinel-OS — FastAPI Application
REST endpoints for agent management, cloud storage, and dynamic policy handling.
"""

from __future__ import annotations

import asyncio
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
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from azure.storage.blob import BlobServiceClient

load_dotenv()

from backend.memory import get_memory_store, SessionStatus
from backend.policy import get_policy_engine

# Silence noisy HTTP logs from Azure SDKs so you can see your agent's reasoning
logging.basicConfig(level=logging.INFO)
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
logging.getLogger("azure.cosmos").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

POLICY_PATH = Path(os.getenv("POLICY_PATH", "config/security_policy.yaml"))

# Always use the real system temp dir — never trust UPLOAD_DIR env on Windows
UPLOAD_DIR = Path(tempfile.gettempdir()) / "honeySentinel_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
logger.info(f"Upload dir: {UPLOAD_DIR}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the default universal policy at startup
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
    return {
        "status": "ok", 
        "policy": policy.summary(), 
        "version": "1.0.0",
        "upload_dir": str(UPLOAD_DIR)
    }


@app.post("/analyse/repo")
async def analyse_repo(request: AnalyseRepoRequest):
    session_id = request.session_id or str(uuid.uuid4())[:12]
    repo_path  = request.repo_path
    if not Path(repo_path).exists():
        raise HTTPException(status_code=400, detail=f"Path not found: {repo_path}")
    
    asyncio.create_task(_run_analysis(session_id, repo_path))
    return {"session_id": session_id, "status": "started"}


@app.post("/analyse/upload")
async def analyse_upload(
    file: UploadFile = File(...),
    policy_file: Optional[UploadFile] = File(None)
):
    """
    Accepts a .zip file of the codebase and an optional custom security_policy.yaml.
    Uploads the zip to Azure Blob Storage for cloud persistence.
    """
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported.")
    
    session_id = str(uuid.uuid4())[:12]
    blob_name = f"{session_id}_{file.filename}"
    
    # --- 1. Handle Custom Security Policy (Optional) ---
    custom_policy_path = None
    if policy_file and policy_file.filename.endswith((".yaml", ".yml")):
        policy_dest = UPLOAD_DIR / f"{session_id}_policy.yaml"
        policy_contents = await policy_file.read()
        policy_dest.write_bytes(policy_contents)
        custom_policy_path = str(policy_dest)
        logger.info(f"[{session_id}] Custom security policy uploaded and applied.")

    contents = await file.read()

    # --- 2. Upload codebase to Azure Blob Storage ---
    conn_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    container_name = os.getenv("AZURE_STORAGE_CONTAINER_NAME", "scanned-repos")
    
    if not conn_str:
        logger.error("🚨 AZURE_STORAGE_CONNECTION_STRING is missing from .env!")
    else:
        try:
            logger.info("Attempting to connect to Azure Blob Storage...")
            blob_service_client = BlobServiceClient.from_connection_string(conn_str)
            container_client = blob_service_client.get_container_client(container_name)
            
            # Auto-create the container if it doesn't exist
            if not container_client.exists():
                logger.info(f"Creating new Blob container: {container_name}")
                container_client.create_container()
                
            blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
            blob_client.upload_blob(contents, overwrite=True)
            logger.info(f"✅ [{session_id}] Uploaded {blob_name} to Azure Blob Storage successfully!")
            
        except Exception as e:
            logger.error(f"🚨 AZURE BLOB STORAGE UPLOAD FAILED: {str(e)}")
            # We log the error but do not raise an exception. 
            # This ensures the Hackathon demo keeps running locally even if the cloud upload fails!

    # --- 3. Save locally for the Agent Tools to scan ---
    dest = UPLOAD_DIR / blob_name
    dest.write_bytes(contents)
    
    # --- 4. Start Analysis in Background ---
    asyncio.create_task(_run_analysis(session_id, str(dest), custom_policy_path))
    
    return {"session_id": session_id, "status": "started", "filename": file.filename}


@app.post("/analyse/github")
async def analyse_github(request: AnalyseGithubRequest):
    session_id = str(uuid.uuid4())[:12]
    github_url = request.github_url.strip()

    if not github_url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    if not shutil.which("git"):
        raise HTTPException(status_code=500, detail="git is not installed on the server.")

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

    asyncio.create_task(_run_analysis(session_id, str(clone_dir)))

    return {
        "session_id": session_id,
        "status":     "started",
        "repo_url":   github_url,
        "clone_dir":  str(clone_dir),
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


async def _run_analysis(session_id: str, path: str, custom_policy_path: str = None) -> None:
    from backend.agents.orchestrator import OrchestratorAgent
    try:
        # Pass the custom policy to the Orchestrator if the user uploaded one
        orch = OrchestratorAgent(session_id=session_id, repo_path=path, policy_path=custom_policy_path)
        await orch.run()
        logger.info(f"[{session_id}] Analysis complete")
    except Exception as e:
        logger.exception(f"[{session_id}] Analysis failed")