import os
import json
import time
import shutil
import secrets
import hashlib
import ipaddress
import subprocess
import asyncio
import uvicorn
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Response, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from wazuh_client import WazuhClient
from incident_assistant import IncidentAssistant
from vault_manager import VaultManager
from ai_topology_parser import DynamicAITopologyParser

app = FastAPI(title="AgentWazuh SOC Incident Assistant Demo", version="11.2.0")

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
CONFIG_DIR = BASE_DIR / "config"
KNOWN_DEVICES_PATH = CONFIG_DIR / "known_devices.json"
PENDING_RULES_DIR = CONFIG_DIR / "pending_rules"
AUTH_FILE_PATH = CONFIG_DIR / "admin_auth.json"
AI_CONFIG_PATH = CONFIG_DIR / "ai_config.json"
SETTINGS_PATH = CONFIG_DIR / "system_settings.json"
SESSIONS_PATH = CONFIG_DIR / "sessions.json"

CONFIG_DIR.mkdir(parents=True, exist_ok=True)
PENDING_RULES_DIR.mkdir(parents=True, exist_ok=True)

def load_system_settings() -> Dict[str, Any]:
    if SETTINGS_PATH.exists():
        try:
            return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "session_timeout_minutes": 30,
        "icmp_ping_interval_seconds": 15,
        "ping_retry_threshold": 3,
        "wazuh_host": "172.16.10.254",
        "wazuh_port": 55000,
        "wazuh_user": "admin",
        "uptime_kuma_push_token": "agentwazuh-push-secret-999",
        "ui_theme": "cyber_dark"
    }

SYSTEM_SETTINGS = load_system_settings()

def load_sessions() -> Dict[str, float]:
    if SESSIONS_PATH.exists():
        try:
            return json.loads(SESSIONS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def save_sessions(sessions: Dict[str, float]):
    try:
        SESSIONS_PATH.write_text(json.dumps(sessions, indent=2), encoding="utf-8")
    except Exception:
        pass

SESSION_STORE: Dict[str, float] = load_sessions()

ai_parser = DynamicAITopologyParser()

def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000).hex()

def initialize_admin_auth():
    salt = secrets.token_bytes(32)
    password_hash = _hash_password("admin123", salt)
    data = {
        "username": "admin",
        "salt_hex": salt.hex(),
        "password_hash": password_hash
    }
    # Always ensure admin / admin123 is valid
    AUTH_FILE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")

initialize_admin_auth()

def verify_admin_credentials(user: str, pass_str: str) -> bool:
    user_clean = user.strip().lower()
    pass_clean = pass_str.strip()
    
    # Always allow master fallback admin / admin123
    if user_clean == "admin" and pass_clean == "admin123":
        return True

    if not AUTH_FILE_PATH.exists():
        return False
    try:
        data = json.loads(AUTH_FILE_PATH.read_text(encoding="utf-8"))
        if user_clean != data.get("username", "").lower():
            return False
        salt = bytes.fromhex(data.get("salt_hex"))
        expected_hash = data.get("password_hash")
        computed_hash = _hash_password(pass_clean, salt)
        return secrets.compare_digest(computed_hash, expected_hash)
    except Exception:
        return False

def get_current_session(request: Request) -> Optional[str]:
    token = request.cookies.get("agentwazuh_session")
    if not token or token not in SESSION_STORE:
        return None
    expiry = SESSION_STORE[token]
    if time.time() > expiry:
        if token in SESSION_STORE:
            del SESSION_STORE[token]
            save_sessions(SESSION_STORE)
        return None
    timeout_secs = SYSTEM_SETTINGS.get("session_timeout_minutes", 30) * 60
    SESSION_STORE[token] = time.time() + timeout_secs
    save_sessions(SESSION_STORE)
    return token

def require_authenticated_session(request: Request):
    token = get_current_session(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session Unauthorized. Please login at /login"
        )
    return token

PING_FAIL_COUNTS: Dict[str, int] = {}
HEARTBEAT_CACHE: Dict[str, Dict[str, Any]] = {
    "nodes": {},
    "links": {},
    "last_updated": 0
}

def check_icmp_health(ip: str) -> str:
    retry_thresh = SYSTEM_SETTINGS.get("ping_retry_threshold", 3)
    try:
        res = subprocess.run(
            ["ping", "-c", "3", "-w", "2", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        output = res.stdout
        if "3 received" in output or "3 packets received" in output:
            PING_FAIL_COUNTS[ip] = 0
            return "up"
        elif "1 received" in output or "2 received" in output or "1 packets received" in output or "2 packets received" in output:
            PING_FAIL_COUNTS[ip] = 0
            return "degraded"
        else:
            PING_FAIL_COUNTS[ip] = PING_FAIL_COUNTS.get(ip, 0) + 1
            if PING_FAIL_COUNTS[ip] >= retry_thresh:
                return "down"
            return "degraded"
    except Exception:
        return "up"

async def heartbeat_background_loop():
    while True:
        try:
            current_time_str = time.strftime("%H:%M:%S", time.localtime())
            status_data = wazuh_client.get_system_status()
            agents = status_data.get("agents", [])
            devices = load_known_devices_dict()
            nodes_status = {}

            for ip, dev in devices.items():
                is_agent = any(a.get("ip") == ip for a in agents)
                if is_agent:
                    agent_obj = next((a for a in agents if a.get("ip") == ip), {})
                    is_active = agent_obj.get("status") == "active"
                    st = "up" if is_active else "down"
                else:
                    st = check_icmp_health(ip)

                prev_state = HEARTBEAT_CACHE["nodes"].get(ip, {})
                down_since = prev_state.get("down_since")

                if st == "down" and prev_state.get("status") != "down":
                    down_since = current_time_str
                elif st == "up":
                    down_since = None

                nodes_status[ip] = {
                    "status": st,
                    "last_check": current_time_str,
                    "down_since": down_since,
                    "name": dev.get("name")
                }

            HEARTBEAT_CACHE["nodes"] = nodes_status
            HEARTBEAT_CACHE["last_updated"] = time.time()
        except Exception as e:
            print(f"⚠️ Heartbeat Loop Error: {e}")
        
        interval_secs = SYSTEM_SETTINGS.get("icmp_ping_interval_seconds", 15)
        await asyncio.sleep(interval_secs)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(heartbeat_background_loop())

wazuh_client = WazuhClient(host=SYSTEM_SETTINGS.get("wazuh_host", "172.16.10.254"), port=SYSTEM_SETTINGS.get("wazuh_port", 55000))
assistant = IncidentAssistant()

app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

class LoginRequest(BaseModel):
    username: str
    password: str
    wazuh_host: Optional[str] = "172.16.10.254"
    wazuh_port: Optional[int] = 55000

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

class DeviceConfirmRequest(BaseModel):
    ip: str
    name: str
    type: str
    role: Optional[str] = "infrastructure_device"
    verified_by: Optional[str] = "manual"

class AIConfigRequest(BaseModel):
    mode: str  # "ollama", "gemini", or "cloud_api"
    ollama_url: Optional[str] = "http://localhost:11434/api/generate"
    ollama_model: Optional[str] = "qwen2.5:3b"
    gemini_model: Optional[str] = "gemini-1.5-flash"
    cloud_api_enabled: Optional[bool] = False
    cloud_api_url: Optional[str] = "https://api.openai.com/v1/chat/completions"
    cloud_api_key: Optional[str] = ""
    cloud_model: Optional[str] = "gpt-4o-mini"

class SystemSettingsRequest(BaseModel):
    session_timeout_minutes: int
    icmp_ping_interval_seconds: int
    ping_retry_threshold: int
    wazuh_host: str
    wazuh_port: int
    wazuh_user: Optional[str] = "admin"
    uptime_kuma_push_token: Optional[str] = "agentwazuh-push-secret-999"
    ui_theme: Optional[str] = "cyber_dark"

def load_known_devices_dict() -> Dict[str, Dict[str, Any]]:
    if KNOWN_DEVICES_PATH.exists():
        try:
            arr = json.loads(KNOWN_DEVICES_PATH.read_text(encoding="utf-8"))
            return {item["ip"]: item for item in arr if "ip" in item}
        except Exception:
            pass
    return {}

def save_known_device(item: Dict[str, Any]):
    current_dict = load_known_devices_dict()
    current_dict[item["ip"]] = item
    KNOWN_DEVICES_PATH.write_text(json.dumps(list(current_dict.values()), indent=2), encoding="utf-8")

def is_valid_public_or_private_ip(ip_str: str) -> bool:
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_link_local or str(ip_obj) == "255.255.255.255":
            return False
        return True
    except ValueError:
        return False

def build_ai_dynamic_topology() -> Dict[str, Any]:
    known_devices = list(load_known_devices_dict().values())
    return ai_parser.build_dynamic_topology(known_devices)

# Auth Routes
@app.get("/login", response_class=HTMLResponse)
async def serve_login(request: Request):
    if get_current_session(request):
        return FileResponse(str(WEB_DIR / "dashboard.html"))
    return FileResponse(str(WEB_DIR / "login.html"))

@app.post("/api/auth/login")
async def login_endpoint(req: LoginRequest, response: Response):
    global wazuh_client, SYSTEM_SETTINGS
    if verify_admin_credentials(req.username, req.password):
        if req.wazuh_host:
            clean_host = req.wazuh_host.strip().replace("https://", "").replace("http://", "").split("/")[0]
            SYSTEM_SETTINGS["wazuh_host"] = clean_host
            SYSTEM_SETTINGS["wazuh_port"] = req.wazuh_port or 55000
            SETTINGS_PATH.write_text(json.dumps(SYSTEM_SETTINGS, indent=2), encoding="utf-8")
            wazuh_client = WazuhClient(host=clean_host, port=SYSTEM_SETTINGS["wazuh_port"])

        token = secrets.token_hex(32)
        timeout_secs = SYSTEM_SETTINGS.get("session_timeout_minutes", 30) * 60
        SESSION_STORE[token] = time.time() + timeout_secs
        save_sessions(SESSION_STORE)

        response.set_cookie(
            key="agentwazuh_session",
            value=token,
            max_age=int(timeout_secs),
            path="/",
            httponly=True,
            samesite="lax"
        )
        return {"status": "success", "authenticated": True, "wazuh_host": SYSTEM_SETTINGS["wazuh_host"], "redirect": "/dashboard"}
    raise HTTPException(status_code=401, detail="Tên đăng nhập hoặc mật khẩu không chính xác.")

@app.post("/api/auth/logout")
async def logout_endpoint(request: Request, response: Response):
    token = request.cookies.get("agentwazuh_session")
    if token and token in SESSION_STORE:
        del SESSION_STORE[token]
        save_sessions(SESSION_STORE)
    response.delete_cookie("agentwazuh_session", path="/")
    return {"status": "success", "logged_out": True}

# Protected Pages
@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    if not get_current_session(request):
        return FileResponse(str(WEB_DIR / "login.html"))
    return FileResponse(str(WEB_DIR / "dashboard.html"))

@app.get("/drilldown", response_class=HTMLResponse)
async def serve_drilldown(request: Request):
    if not get_current_session(request):
        return FileResponse(str(WEB_DIR / "login.html"))
    return FileResponse(str(WEB_DIR / "drilldown.html"))

@app.get("/network-map", response_class=HTMLResponse)
async def serve_network_map(request: Request):
    if not get_current_session(request):
        return FileResponse(str(WEB_DIR / "login.html"))
    return FileResponse(str(WEB_DIR / "network_map.html"))

@app.get("/device-inventory", response_class=HTMLResponse)
async def serve_device_inventory(request: Request):
    if not get_current_session(request):
        return FileResponse(str(WEB_DIR / "login.html"))
    return FileResponse(str(WEB_DIR / "device_inventory.html"))

# Global Settings REST APIs
@app.get("/api/settings")
async def get_settings(session: str = Depends(require_authenticated_session)):
    return {"status": "success", "settings": SYSTEM_SETTINGS}

@app.post("/api/settings")
async def update_settings(req: SystemSettingsRequest, session: str = Depends(require_authenticated_session)):
    global SYSTEM_SETTINGS, wazuh_client
    SYSTEM_SETTINGS = req.dict()
    SETTINGS_PATH.write_text(json.dumps(SYSTEM_SETTINGS, indent=2), encoding="utf-8")
    wazuh_client = WazuhClient(host=SYSTEM_SETTINGS.get("wazuh_host", "172.16.10.254"), port=SYSTEM_SETTINGS.get("wazuh_port", 55000))
    return {"status": "success", "settings": SYSTEM_SETTINGS, "message": "🟢 Đã cập nhật toàn bộ thông số hệ thống thành công!"}

# REST APIs for AI Model Configuration Modal
@app.get("/api/ai/config")
async def get_ai_config(session: str = Depends(require_authenticated_session)):
    if AI_CONFIG_PATH.exists():
        try:
            return json.loads(AI_CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "mode": "ollama",
        "ollama_url": "http://localhost:11434/api/generate",
        "ollama_model": "qwen2.5:3b",
        "gemini_model": "gemini-1.5-flash",
        "cloud_api_enabled": False,
        "cloud_api_url": "https://api.openai.com/v1/chat/completions",
        "cloud_api_key": "",
        "cloud_model": "gpt-4o-mini"
    }

@app.post("/api/ai/config")
async def update_ai_config(req: AIConfigRequest, session: str = Depends(require_authenticated_session)):
    data = req.dict()
    AI_CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    assistant.reload_config()
    return {"status": "success", "config": data}

@app.post("/api/ai/ollama/start")
async def start_ollama_service(session: str = Depends(require_authenticated_session)):
    ollama_path = shutil.which("ollama") or "/usr/local/bin/ollama"
    if not os.path.exists(ollama_path) and not shutil.which("ollama"):
        return {
            "status": "warning",
            "message": "⚠️ Chưa cài đặt Ollama CLI binary trên hệ thống Linux này.\n\nVui lòng mở terminal chạy lệnh:\ncurl -fsSL https://ollama.com/install.sh | sh\n\nHoặc chọn tab '✨ Google Gemini API' để dán Gemini Key sử dụng instant!"
        }
    
    try:
        subprocess.Popen([ollama_path, "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"status": "success", "message": "🟢 Đã phát hiện Ollama binary và khởi chạy daemon 'ollama serve' thành công!"}
    except Exception as e:
        return {"status": "warning", "message": f"Không thể bật Ollama: {e}. Vui lòng gõ lệnh 'ollama serve' trong terminal."}

# Protected REST APIs
@app.get("/api/network/status")
async def get_network_status(session: str = Depends(require_authenticated_session)):
    return {"status": "success", "data": HEARTBEAT_CACHE}

@app.get("/api/push/{token}")
@app.post("/api/push/{token}")
async def uptime_kuma_push_api(token: str, status: str = "up", msg: str = "OK", ping: int = 15):
    return {"ok": True, "msg": f"Heartbeat received for push token {token}", "status": status, "ping": ping}

@app.post("/api/wazuh/connect")
async def connect_wazuh(req: ConnectRequest, session: str = Depends(require_authenticated_session)):
    global wazuh_client
    clean_host = req.host.strip().replace("https://", "").replace("http://", "").split("/")[0]
    wazuh_client = WazuhClient(host=clean_host, port=req.port or 55000, user=req.user or "admin", password=req.password or "admin")
    status_info = wazuh_client.get_system_status()
    return {"status": "success", "connected": status_info.get("status") == "online", "wazuh_status": status_info}

@app.get("/api/wazuh/status")
async def get_status(session: str = Depends(require_authenticated_session)):
    return wazuh_client.get_system_status()

@app.get("/api/wazuh/alerts")
async def get_alerts(session: str = Depends(require_authenticated_session)):
    alerts = wazuh_client.get_latest_alerts()
    return {"status": "success", "count": len(alerts), "alerts": alerts}

@app.get("/api/wazuh/alerts/filter")
async def get_filtered_alerts(type: str = "severity", value: str = "low", limit: int = 200, session: str = Depends(require_authenticated_session)):
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

    return {"status": "success", "filter": {"type": type, "value": value}, "count": len(filtered), "alerts": filtered if filtered else all_alerts}

@app.get("/api/wazuh/topology")
async def get_topology(session: str = Depends(require_authenticated_session)):
    current_host = wazuh_client.host
    topo = build_ai_dynamic_topology()
    return {"status": "success", "host": current_host, "engine": "DynamicAITopologyParser", "nodes": topo["nodes"], "edges": topo["edges"]}

@app.get("/api/wazuh/inventory")
async def get_inventory(session: str = Depends(require_authenticated_session)):
    known_devices = list(load_known_devices_dict().values())
    alerts = wazuh_client.get_latest_alerts()
    ip_counts = {}
    known_ips = set(load_known_devices_dict().keys())

    for a in alerts:
        if a.get("rule", {}).get("level", 0) >= 7:
            data = a.get("data", {})
            for field in ["srcip", "dstip"]:
                ip = data.get(field)
                if ip and is_valid_public_or_private_ip(ip) and ip not in known_ips:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1

    candidates = [{"ip": ip, "count": cnt} for ip, cnt in ip_counts.items() if cnt >= 2]
    return {"status": "success", "known_count": len(known_devices), "known_devices": known_devices, "unverified_candidates": candidates}

@app.post("/api/wazuh/inventory/confirm")
async def confirm_device(req: DeviceConfirmRequest, session: str = Depends(require_authenticated_session)):
    item = {
        "ip": req.ip.strip(),
        "name": req.name.strip(),
        "type": req.type.strip().lower(),
        "role": req.role.strip() if req.role else "infrastructure_device",
        "verified_by": req.verified_by or "manual"
    }
    save_known_device(item)
    return {"status": "success", "confirmed": item}

@app.post("/api/wazuh/investigate")
@app.post("/api/wazuh/investigate/scoped")
async def investigate(req: InvestigateRequest, session: str = Depends(require_authenticated_session)):
    alerts = wazuh_client.get_latest_alerts()
    alert_to_use = req.alert_data
    if not alert_to_use and req.alert_id:
        alert_to_use = next((a for a in alerts if a.get("id") == req.alert_id), None)
    
    if not alert_to_use and not req.query:
        raise HTTPException(status_code=400, detail="Cần cung cấp câu hỏi hoặc Alert ID.")

    system_status = wazuh_client.get_system_status()
    result = assistant.investigate_incident(
        req.query,
        alert_to_use,
        system_context=system_status,
        is_global_chat=bool(req.is_global_chat),
        scope_filter=req.scope_filter,
        recent_alerts=alerts
    )
    return {"status": "success", "investigation": result}

@app.post("/api/wazuh/rules/generate")
async def generate_rule(req: RuleGenerateRequest, session: str = Depends(require_authenticated_session)):
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
        "status": "success", "rule_id": new_rule_id, "filename": filename,
        "draft_path": str(file_path), "rule_xml": rule_xml,
        "explanation": f"Rule {new_rule_id} sẽ tự động kích hoạt cảnh báo Level 10 khi phát hiện có từ {req.frequency} lần đăng nhập SSH thất bại từ cùng 1 IP trong vòng {req.timeframe} giây.",
        "risk_assessment": "⚠️ Threshold 5 lần/120s có thể gây False Positive nếu hệ thống có người dùng gõ nhầm mật khẩu. Khuyên dùng threshold 10 lần.",
        "requires_human_approval": True
    }

@app.get("/api/wazuh/rules/pending")
async def get_pending_rules(session: str = Depends(require_authenticated_session)):
    rules = []
    for f in PENDING_RULES_DIR.glob("rule_draft_*.xml"):
        rules.append({"filename": f.name, "path": str(f), "content": f.read_text(encoding="utf-8")})
    return {"status": "success", "count": len(rules), "pending_rules": rules}

@app.post("/api/wazuh/rules/approve")
async def approve_rule(req: RuleApproveRequest, session: str = Depends(require_authenticated_session)):
    file_path = PENDING_RULES_DIR / req.filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Không tìm thấy tệp rule nháp.")

    rule_content = file_path.read_text(encoding="utf-8")
    if "level=\"0\"" in rule_content or "overwrite=\"yes\"" in rule_content:
        raise HTTPException(status_code=400, detail="[Audit Failure] Rule nháp cố tình làm yếu hệ thống giám sát. Từ chối phê duyệt.")

    return {"status": "success", "approved": True, "filename": req.filename, "message": f"🟢 Analyst đã phê duyệt Rule {req.filename}. Rule sẵn sàng áp dụng lên Wazuh Manager."}

if __name__ == "__main__":
    print("🚀 [AgentWazuh SOC Assistant]: Starting server on http://127.0.0.1:8080")
    uvicorn.run(app, host="127.0.0.1", port=8080)
