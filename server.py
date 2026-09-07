import os
import subprocess
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from core.orchestrator import MultiAgentOrchestrator
from core.file_explorer import FileExplorer
from core.history_manager import HistoryManager
from core.memory_engine import PersistentMemoryEngine
from services.incident_assistant import IncidentAssistantService
from mcp_layer.correlation_mcp import search_correlated_events


app = FastAPI(title="AgentCraft 6.0 Memory & RAG Skill IDE Backend", version="6.0")

# Mount Web Static Assets
web_dir = Path(__file__).parent / "web"
app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")

CURRENT_WORKSPACE = os.getenv("TARGET_WORKSPACE", "/home/kweismann")
orchestrator = MultiAgentOrchestrator(workspace_dir=CURRENT_WORKSPACE)
history_mgr = HistoryManager()
memory_engine = PersistentMemoryEngine()

GLOBAL_METRICS = {
    "total_tokens": 13499,
    "architect_tokens": 4957,
    "coder_tokens": 5440,
    "auditor_tokens": 3102,
    "tokens_saved_by_muncher": 6074,
    "estimated_cost_usd": 0.010122,
    "execution_count": 1
}

SETTINGS_STATE = {
    "security_preset": "Turbo Mode",
    "artifact_review_policy": "Always Ask",
    "file_access_rules": "Open",
    "network_access_rules": "Open",
    "terminal_commands": "Open",
    "commands_outside_sandbox": "Open"
}

class RunRequest(BaseModel):
    prompt: str
    stack: Optional[List[str]] = ["python", "clean-code"]
    workspace: Optional[str] = None
    architect_model: Optional[str] = "gemini-2.5-pro"
    coder_model: Optional[str] = "gpt-4o"
    auditor_model: Optional[str] = "claude-3.5-sonnet"
    session_id: Optional[str] = None

class WorkspaceRequest(BaseModel):
    workspace: str

class ExecuteFileRequest(BaseModel):
    filepath: str

class CorrelationRequest(BaseModel):
    target_ip: str
    base_timestamp: Optional[str] = "2026-09-07T16:00:00Z"
    time_window_minutes: Optional[int] = 15
    rule_level: Optional[int] = 12
    rule_id: Optional[str] = "100015"
    rule_description: Optional[str] = "SSH brute force attempt detected"
    agent_name: Optional[str] = "PC-PB1-VLAN10"

@app.post("/api/wazuh/correlation")
def analyze_correlation(req: CorrelationRequest):
    alert_payload = {
        "rule": {
            "id": req.rule_id,
            "level": req.rule_level,
            "description": req.rule_description
        },
        "agent": {
            "name": req.agent_name
        },
        "data": {
            "srcip": req.target_ip
        },
        "timestamp": req.base_timestamp
    }
    incident_service = IncidentAssistantService()
    result = incident_service.analyze_incident(alert_payload)
    return result

@app.get("/", response_class=HTMLResponse)
def read_root():
    index_file = web_dir / "index.html"
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))

@app.get("/api/status")
def get_status():
    return {
        "status": "online",
        "system": "CachyOS Linux",
        "workspace": CURRENT_WORKSPACE,
        "settings": SETTINGS_STATE,
        "api_keys": {
            "gemini": bool(os.getenv("GEMINI_API_KEY")),
            "openai": bool(os.getenv("OPENAI_API_KEY")),
            "openrouter": bool(os.getenv("OPENROUTER_API_KEY")),
        },
        "metrics": GLOBAL_METRICS
    }

@app.get("/api/memory")
def get_memory():
    return {"memories": memory_engine.memories}

@app.get("/api/settings")
def get_settings():
    return {"settings": SETTINGS_STATE}

@app.post("/api/settings")
def update_settings(data: Dict[str, Any]):
    SETTINGS_STATE.update(data)
    return {"success": True, "settings": SETTINGS_STATE}

@app.get("/api/browse")
def browse_directory(path: Optional[str] = "/"):
    target_path = Path(path).resolve() if path else Path("/")
    if not target_path.exists() or not target_path.is_dir():
        target_path = Path("/home/kweismann")

    entries = []
    try:
        for item in target_path.iterdir():
            entries.append({
                "name": item.name,
                "path": str(item),
                "is_dir": item.is_dir(),
                "size": item.stat().st_size if item.is_file() else 0
            })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return {
        "current_path": str(target_path),
        "parent_path": str(target_path.parent),
        "entries": entries
    }

@app.get("/api/file-tree")
def get_file_tree(path: Optional[str] = None):
    target = path or CURRENT_WORKSPACE
    return {"file_tree": FileExplorer.get_project_file_tree(target)}

@app.get("/api/read-file")
def read_file(path: str):
    file_path = Path(path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    try:
        content = file_path.read_text(encoding="utf-8")
        return {"content": content, "path": str(file_path)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {e}")

@app.post("/api/execute-file")
def execute_file(req: ExecuteFileRequest):
    result = FileExplorer.execute_file(req.filepath)
    return result

@app.get("/api/autocomplete")
def autocomplete_files(workspace: str, query: str = ""):
    suggestions = FileExplorer.autocomplete_file(workspace, query)
    return {"suggestions": suggestions}

@app.post("/api/set-workspace")
def set_workspace(req: WorkspaceRequest):
    global CURRENT_WORKSPACE
    target_path = Path(req.workspace).resolve()
    if not target_path.exists():
        raise HTTPException(status_code=404, detail=f"Workspace path does not exist: {req.workspace}")
    CURRENT_WORKSPACE = str(target_path)
    return {"success": True, "workspace": CURRENT_WORKSPACE, "file_tree": FileExplorer.get_project_file_tree(CURRENT_WORKSPACE)}

@app.get("/api/history")
def get_history():
    return {"history": history_mgr.get_all_history()}

@app.get("/api/reports")
def get_reports():
    reports_dir = Path("/home/kweismann/.gemini/antigravity/brain/76f27bff-a812-434a-aff8-32bee09f586a")
    reports = []

    local_guide = Path("/run/media/kweismann/Dir_D/MutiAgent/API_GUIDE.md")
    if local_guide.exists():
        reports.append({"title": "API_GUIDE.md - Hướng Dẫn API Key", "type": "guide", "content": local_guide.read_text(encoding="utf-8")})

    if reports_dir.exists():
        for file in reports_dir.glob("*.md"):
            reports.append({"title": file.name, "type": "plan" if "plan" in file.name else "walkthrough", "content": file.read_text(encoding="utf-8")})

    return {"reports": reports}

@app.post("/api/run")
def run_workflow(req: RunRequest):
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt requirement cannot be empty")

    target_ws = req.workspace or CURRENT_WORKSPACE
    result = orchestrator.run_feature_workflow(
        req.prompt,
        req.stack or ["python"],
        target_workspace=target_ws,
        architect_model=req.architect_model or "gemini-2.5-pro",
        coder_model=req.coder_model or "gpt-4o",
        auditor_model=req.auditor_model or "claude-3.5-sonnet",
        session_id=req.session_id
    )

    tokens_used = result.get("tokens_used", {})
    total = tokens_used.get("total", 0)
    
    GLOBAL_METRICS["execution_count"] += 1
    GLOBAL_METRICS["total_tokens"] += total
    GLOBAL_METRICS["architect_tokens"] += tokens_used.get("architect", 0)
    GLOBAL_METRICS["coder_tokens"] += tokens_used.get("coder", 0)
    GLOBAL_METRICS["auditor_tokens"] += tokens_used.get("auditor", 0)
    
    cost = (tokens_used.get("coder", 0) * 0.00000015) + (tokens_used.get("auditor", 0) * 0.000003)
    GLOBAL_METRICS["estimated_cost_usd"] += cost
    GLOBAL_METRICS["tokens_saved_by_muncher"] += int(total * 0.45)

    return {
        "success": True,
        "result": result,
        "metrics": GLOBAL_METRICS
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
