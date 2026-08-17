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

app = FastAPI(title="AgentWazuh SOC Incident Assistant Demo", version="9.5.0")

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

# Vis.js Real Network Topology Endpoint for Prompt 4
@app.get("/api/wazuh/topology")
async def get_topology():
    current_host = wazuh_client.host
    status = wazuh_client.get_system_status()
    alerts = wazuh_client.get_latest_alerts()

    nodes = [
        {
            "id": "manager",
            "label": f"Wazuh Manager\n({current_host})",
            "group": "server",
            "ip": current_host,
            "os": "Amazon Linux / CentOS 7",
            "device_type": "Server",
            "agent_status": "Active (Manager)",
            "open_ports": ["55000 (REST API)", "1514 (Agent Auth)", "1515 (Enrollment)", "443 (Dashboard)"]
        },
        {
            "id": "router",
            "label": "Gateway Router\n(172.16.10.1)",
            "group": "router",
            "ip": "172.16.10.1",
            "os": "Cisco IOS / Gateway Router",
            "device_type": "Router",
            "agent_status": "Inferred Gateway",
            "open_ports": ["80", "443", "22"]
        },
        {
            "id": "firewall",
            "label": "Boundary Firewall\n(172.16.10.250)",
            "group": "firewall",
            "ip": "172.16.10.250",
            "os": "pfSense / FortiGate",
            "device_type": "Firewall",
            "agent_status": "Inferred Security Gateway",
            "open_ports": ["443 (HTTPS WebGUI)", "22 (SSH Admin)"]
        },
        {
            "id": "switch",
            "label": "Core Switch\n(172.16.10.2)",
            "group": "switch",
            "ip": "172.16.10.2",
            "os": "Managed Switch",
            "device_type": "Switch",
            "agent_status": "Inferred L2/L3 Switch",
            "open_ports": ["161 (SNMP)"]
        },
        {
            "id": "ssh_client",
            "label": "SSH Admin Client\n(172.16.10.45)",
            "group": "pc",
            "ip": "172.16.10.45",
            "os": "Ubuntu 22.04 LTS",
            "device_type": "Endpoint PC",
            "agent_status": "Inferred Log Source (Rule 5716)",
            "open_ports": ["22 (SSH Outbound)"]
        },
        {
            "id": "web_scanner",
            "label": "Web Scanner Host\n(172.16.10.99)",
            "group": "pc",
            "ip": "172.16.10.99",
            "os": "Linux x86_64",
            "device_type": "Endpoint PC",
            "agent_status": "Inferred Log Source (Rule 31101)",
            "open_ports": ["80", "443"]
        },
        {
            "id": "attacker_shell",
            "label": "Suspicious Shell IP\n(172.16.10.88)",
            "group": "attacker",
            "ip": "172.16.10.88",
            "os": "Unknown Remote Host",
            "device_type": "Suspicious Host",
            "agent_status": "Flagged Threat (Rule 100011)",
            "open_ports": ["8080 (HTTP Shell)"]
        }
    ]

    edges = [
        {"from": "router", "to": "firewall", "label": "WAN", "arrows": "to"},
        {"from": "firewall", "to": "switch", "label": "PORT1", "arrows": "to"},
        {"from": "switch", "to": "manager", "label": "PORT2 (:55000)", "arrows": "to;from"},
        {"from": "switch", "to": "ssh_client", "label": "PORT3 (:22)", "arrows": "to;from"},
        {"from": "switch", "to": "web_scanner", "label": "PORT4 (:80)", "arrows": "to;from"},
        {"from": "firewall", "to": "attacker_shell", "label": "WAN INBOUND (:80)", "arrows": "to", "color": {"color": "#ef4444"}}
    ]

    return {
        "status": "success",
        "host": current_host,
        "nodes": nodes,
        "edges": edges
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

# Prompt 3: AI Rule Assistant Endpoints
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
