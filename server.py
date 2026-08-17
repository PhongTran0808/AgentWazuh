import os
import uvicorn
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any

from wazuh_client import WazuhClient
from incident_assistant import IncidentAssistant

app = FastAPI(title="AgentWazuh SOC Incident Assistant Demo", version="1.0.0")

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"

wazuh_client = WazuhClient(host="192.168.1.240")
assistant = IncidentAssistant()

app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

class InvestigateRequest(BaseModel):
    query: str
    alert_id: Optional[str] = None
    alert_data: Optional[Dict[str, Any]] = None
    is_global_chat: Optional[bool] = False

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = WEB_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return HTMLResponse("<h2>AgentWazuh SOC Assistant Dashboard</h2>")

@app.get("/api/wazuh/status")
async def get_status():
    return wazuh_client.get_system_status()

@app.get("/api/wazuh/alerts")
async def get_alerts():
    alerts = wazuh_client.get_latest_alerts()
    return {"status": "success", "count": len(alerts), "alerts": alerts}

@app.post("/api/wazuh/investigate")
async def investigate(req: InvestigateRequest):
    alert_to_use = req.alert_data
    if not alert_to_use and req.alert_id:
        alerts = wazuh_client.get_latest_alerts()
        alert_to_use = next((a for a in alerts if a.get("id") == req.alert_id), None)
    
    if not alert_to_use and not req.query:
        raise HTTPException(status_code=400, detail="Cần cung cấp câu hỏi hoặc Alert ID.")

    system_status = wazuh_client.get_system_status()
    result = assistant.investigate_incident(
        req.query,
        alert_to_use,
        system_context=system_status,
        is_global_chat=bool(req.is_global_chat)
    )
    return {"status": "success", "investigation": result}

if __name__ == "__main__":
    print("🚀 [AgentWazuh SOC Assistant]: Starting server on http://127.0.0.1:8080")
    uvicorn.run(app, host="127.0.0.1", port=8080)
