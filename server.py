import os
import json
import time
import uvicorn
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from wazuh_client import WazuhClient
from incident_assistant import IncidentAssistant

app = FastAPI(title="AgentWazuh SOC Incident Assistant Demo", version="9.0.0")

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
PENDING_RULES_DIR = BASE_DIR / "config" / "pending_rules"
PENDING_RULES_DIR.mkdir(parents=True, exist_ok=True)

# Default client
wazuh_client = WazuhClient(host="172.16.10.254")
assistant = IncidentAssistant()

app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

class ConnectRequest(BaseModel):
    host: str
    port: Optional[int] = 55000
    user: Optional[str] = "admin"
    password: Optional[str] = "admin"

class InvestigateRequest(BaseModel):
    query: str
    alert_id: Optional[str] = None
    alert_data: Optional[Dict[str, Any]] = None
    is_global_chat: Optional[bool] = False
    scope_filter: Optional[Dict[str, Any]] = None

class RuleGenerateRequest(BaseModel):
    prompt: str
    timeframe: Optional[int] = 120
    frequency: Optional[int] = 5

class RuleApproveRequest(BaseModel):
    filename: str

# Page Routes
@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
async def serve_login():
    login_path = WEB_DIR / "login.html"
    if login_path.exists():
        return FileResponse(str(login_path))
    return HTMLResponse("<h2>AgentWazuh Login Page</h2>")

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    dash_path = WEB_DIR / "dashboard.html"
    if dash_path.exists():
        return FileResponse(str(dash_path))
    return HTMLResponse("<h2>AgentWazuh Dashboard Page</h2>")

@app.get("/drilldown", response_class=HTMLResponse)
async def serve_drilldown():
    drill_path = WEB_DIR / "drilldown.html"
    if drill_path.exists():
        return FileResponse(str(drill_path))
    return HTMLResponse("<h2>AgentWazuh Drilldown Page</h2>")

@app.get("/network-map", response_class=HTMLResponse)
async def serve_network_map():
    map_path = WEB_DIR / "network_map.html"
    if map_path.exists():
        return FileResponse(str(map_path))
    return HTMLResponse("<h2>AgentWazuh Network Map Page</h2>")

# API Endpoints
@app.post("/api/wazuh/connect")
async def connect_wazuh(req: ConnectRequest):
    global wazuh_client
    clean_host = req.host.strip().replace("https://", "").replace("http://", "").split("/")[0]
    wazuh_client = WazuhClient(host=clean_host, port=req.port or 55000, user=req.user or "admin", password=req.password or "admin")
    status = wazuh_client.get_system_status()
    return {
        "status": "success",
        "connected": status.get("status") == "online",
        "wazuh_status": status
    }

@app.get("/api/wazuh/status")
async def get_status():
    return wazuh_client.get_system_status()

@app.get("/api/wazuh/alerts")
async def get_alerts():
    alerts = wazuh_client.get_latest_alerts()
    return {"status": "success", "count": len(alerts), "alerts": alerts}

@app.get("/api/wazuh/alerts/filter")
async def get_filtered_alerts(type: str = "severity", value: str = "low", limit: int = 200):
    all_alerts = wazuh_client.get_latest_alerts()
    filtered = []
    
    val_lower = value.lower()
    for a in all_alerts:
        level = a.get("rule", {}).get("level", 0)
        rule_id = str(a.get("rule", {}).get("id"))
        
        if type == "severity":
            if val_lower == "critical" and level >= 15: filtered.append(a)
            elif val_lower == "high" and 12 <= level < 15: filtered.append(a)
            elif val_lower == "medium" and 7 <= level < 12: filtered.append(a)
            elif val_lower == "low" and level < 7: filtered.append(a)
            elif val_lower == "total": filtered.append(a)
        elif type == "rule" and rule_id == value:
            filtered.append(a)
        elif type == "agent":
            filtered.append(a)

    return {
        "status": "success",
        "filter": {"type": type, "value": value},
        "count": len(filtered),
        "alerts": filtered if filtered else all_alerts
    }

@app.post("/api/wazuh/investigate")
@app.post("/api/wazuh/investigate/scoped")
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
        is_global_chat=bool(req.is_global_chat),
        scope_filter=req.scope_filter
    )
    return {"status": "success", "investigation": result}

# Prompt 3: AI Rule Assistant Endpoints (Human Review & Draft Staging)
@app.post("/api/wazuh/rules/generate")
async def generate_rule(req: RuleGenerateRequest):
    timestamp = int(time.time())
    new_rule_id = 100026
    
    rule_xml = f"""<group name="sshd,authentication_failures,">
  <rule id="{new_rule_id}" level="10">
    <if_matched_sid>5716</if_matched_sid>
    <same_source_ip />
    <frequency>{req.frequency}</frequency>
    <timeframe>{req.timeframe}</timeframe>
    <description>AI Generated Rule: SSH Brute Force ({req.frequency} failures in {req.timeframe}s)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>
</group>"""

    filename = f"rule_draft_{timestamp}.xml"
    file_path = PENDING_RULES_DIR / filename
    file_path.write_text(rule_xml, encoding="utf-8")

    return {
        "status": "success",
        "rule_id": new_rule_id,
        "filename": filename,
        "draft_path": str(file_path),
        "rule_xml": rule_xml,
        "explanation": f"Rule {new_rule_id} sẽ tự động kích hoạt cảnh báo Level 10 khi phát hiện có từ {req.frequency} lần đăng nhập SSH thất bại từ cùng 1 IP trong vòng {req.timeframe} giây.",
        "risk_assessment": "⚠️ Threshold 5 lần/120s có thể gây False Positive nếu hệ thống có người dùng gõ nhầm mật khẩu. Khuyên dùng threshold 10 lần.",
        "requires_human_approval": True
    }

@app.get("/api/wazuh/rules/pending")
async def get_pending_rules():
    rules = []
    for f in PENDING_RULES_DIR.glob("rule_draft_*.xml"):
        rules.append({
            "filename": f.name,
            "path": str(f),
            "content": f.read_text(encoding="utf-8")
        })
    return {"status": "success", "count": len(rules), "pending_rules": rules}

@app.post("/api/wazuh/rules/approve")
async def approve_rule(req: RuleApproveRequest):
    file_path = PENDING_RULES_DIR / req.filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp rule nháp.")

    rule_content = file_path.read_text(encoding="utf-8")
    
    # Audit Safety Check by @reviewer: Verify rule doesn't modify system rules
    if "level=\"0\"" in rule_content or "overwrite=\"yes\"" in rule_content:
        raise HTTPException(status_code=400, detail="[Audit Failure] Rule nháp cố tình làm yếu hệ thống giám sát. Từ chối phê duyệt.")

    return {
        "status": "success",
        "approved": True,
        "filename": req.filename,
        "message": f"🟢 Analyst đã phê duyệt Rule {req.filename}. Rule sẵn sàng áp dụng lên Wazuh Manager."
    }

if __name__ == "__main__":
    print("🚀 [AgentWazuh SOC Assistant]: Starting server on http://127.0.0.1:8080")
    uvicorn.run(app, host="127.0.0.1", port=8080)
