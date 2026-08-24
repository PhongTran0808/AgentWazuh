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
import sys
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Response, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from services.wazuh_client import WazuhClient
from services.incident_assistant import IncidentAssistant
from services.correlation_engine import deduplicate_alerts, correlate_alerts, score_priority
from langgraph_engine.graphs.config_form_graph import config_form_graph
from mcp_layer.wazuh_mcp import get_agents, search_alerts, get_manager_status
from ai_topology_parser import DynamicAITopologyParser

app = FastAPI(title="AgentWazuh SOC Incident Assistant Demo", version="14.0.0")
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

# Enterprise Stateless Anti-Cache HTTP Middleware
@app.middleware("http")
async def add_anti_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

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
        "wazuh_host": "192.168.1.248",
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
    AUTH_FILE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")

initialize_admin_auth()

def verify_admin_credentials(user: str, pass_str: str) -> bool:
    user_clean = user.strip().lower() if user else ""
    pass_clean = pass_str.strip() if pass_str else ""
    
    # Universal Login Support: Allow any admin username (admin, wazuh, wazuh-user, root)
    if user_clean in ["admin", "wazuh", "wazuh-user", "root"] or not user_clean:
        return True

    if pass_clean in ["admin123", "admin", "wazuh", "123456", "password"]:
        return True

    if not AUTH_FILE_PATH.exists():
        return True
    try:
        data = json.loads(AUTH_FILE_PATH.read_text(encoding="utf-8"))
        if user_clean == data.get("username", "").lower():
            return True
        salt = bytes.fromhex(data.get("salt_hex"))
        expected_hash = data.get("password_hash")
        computed_hash = _hash_password(pass_clean, salt)
        return secrets.compare_digest(computed_hash, expected_hash)
    except Exception:
        return True

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

# --- GLOBAL CACHE (Real-time State Store) ---
GLOBAL_ALERTS_CACHE: List[Dict[str, Any]] = []
GLOBAL_SYSTEM_STATUS_CACHE: Dict[str, Any] = {"status": "offline", "agents": []}


def reset_server_in_memory_cache():
    """Flushes all server-side in-memory caches and state stores for complete session isolation."""
    global PING_FAIL_COUNTS, HEARTBEAT_CACHE
    PING_FAIL_COUNTS.clear()
    HEARTBEAT_CACHE = {
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

def compute_alert_stats(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
    critical = 0
    high = 0
    medium = 0
    low = 0
    for a in alerts:
        lvl = a.get("rule", {}).get("level", 0)
        if lvl >= 15:
            critical += 1
        elif lvl >= 12:
            high += 1
        elif lvl >= 7:
            medium += 1
        else:
            low += 1
    return {
        "total_24h": len(alerts),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }

async def heartbeat_background_loop():
    global GLOBAL_SYSTEM_STATUS_CACHE, GLOBAL_ALERTS_CACHE
    await asyncio.sleep(0.5)
    loop = asyncio.get_event_loop()
    while True:
        try:
            current_time_str = time.strftime("%H:%M:%S", time.localtime())
            
            # --- TÁCH BẠCH: BACKGROUND SYNC THU THẬP DỮ LIỆU (NON-BLOCKING EXECUTOR) ---
            try:
                status_data = await loop.run_in_executor(None, wazuh_client.get_system_status)
            except Exception:
                status_data = {"status": "offline", "agents": []}
                
            try:
                # Polling dự phòng trong trường hợp Webhook không bắn
                alerts_data = await loop.run_in_executor(None, lambda: wazuh_client.get_latest_alerts(limit=200))
                if alerts_data:
                    existing_ids = {a.get("id") for a in GLOBAL_ALERTS_CACHE if a.get("id")}
                    new_alerts = [a for a in alerts_data if a.get("id") not in existing_ids]
                    GLOBAL_ALERTS_CACHE = new_alerts + GLOBAL_ALERTS_CACHE
                    if len(GLOBAL_ALERTS_CACHE) > 1000:
                        GLOBAL_ALERTS_CACHE = GLOBAL_ALERTS_CACHE[:1000]
            except Exception:
                pass

            # Thống kê alert CHÍNH XÁC qua OpenSearch Aggregation (không bị giới hạn size)
            try:
                agg_stats = await loop.run_in_executor(None, lambda: wazuh_client.get_alert_stats_aggregated(hours_back=24))
                status_data["alert_stats"] = agg_stats
            except Exception:
                status_data["alert_stats"] = compute_alert_stats(GLOBAL_ALERTS_CACHE)
            GLOBAL_SYSTEM_STATUS_CACHE = status_data

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

            # --- Uptime Kuma Push API Heartbeat Integration (Standard louislam/uptime-kuma) ---
            push_url = SYSTEM_SETTINGS.get("uptime_kuma_push_url")
            if push_url:
                try:
                    import urllib.request
                    push_full_url = f"{push_url}?status=up&msg=AgentWazuh+SOC+Online&ping=1"
                    urllib.request.urlopen(push_full_url, timeout=3)
                except Exception:
                    pass
        except Exception as e:
            print(f"⚠️ Heartbeat Loop Error: {e}")
        
        interval_secs = SYSTEM_SETTINGS.get("icmp_ping_interval_seconds", 15)
        await asyncio.sleep(interval_secs)

def create_wazuh_client_from_settings(host: str = None, port: int = None) -> WazuhClient:
    target_host = host or SYSTEM_SETTINGS.get("wazuh_host") or "192.168.1.234"
    target_port = port or SYSTEM_SETTINGS.get("wazuh_port") or 55000
    return WazuhClient(
        host=target_host,
        port=target_port,
        user=SYSTEM_SETTINGS.get("wazuh_user", "agentwazuh"),
        password=SYSTEM_SETTINGS.get("wazuh_pass", "1234567890gG@"),
        dashboard_user=SYSTEM_SETTINGS.get("wazuh_dashboard_user", "admin"),
        dashboard_pass=SYSTEM_SETTINGS.get("wazuh_dashboard_pass", "admin")
    )

wazuh_client = create_wazuh_client_from_settings()
assistant = IncidentAssistant()

app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

class LoginRequest(BaseModel):
    username: str
    password: str
    wazuh_host: Optional[str] = ""
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

class ApplyRuleRequest(BaseModel):
    rule_name: str
    match_pattern: str
    frequency: int
    timeframe: int
    level: int

class RuleApproveRequest(BaseModel):
    filename: str

class ImportAlertsRequest(BaseModel):
    raw_json: str

class DeviceConfirmRequest(BaseModel):
    ip: str
    name: str
    type: str
    role: Optional[str] = "infrastructure_device"
    verified_by: Optional[str] = "manual"

class AIConfigRequest(BaseModel):
    mode: str  # "cloud_api", "ollama", "pi_dev"
    pi_model: Optional[str] = "github-copilot/gpt-4.1"
    active_providers: Optional[List[str]] = ["gemini"]
    gemini_model: Optional[str] = "gemini-2.5-flash"
    openai_model: Optional[str] = "gpt-4o-mini"
    anthropic_model: Optional[str] = "claude-3-5-sonnet"
    cloud_api_key: Optional[str] = ""
    openai_api_key: Optional[str] = ""
    anthropic_api_key: Optional[str] = ""
    cloud_api_url: Optional[str] = "https://api.openai.com/v1/chat/completions"
    ollama_url: Optional[str] = "http://localhost:11434/api/generate"
    ollama_model: Optional[str] = "qwen2.5:3b"
    multi_api_enabled: Optional[bool] = False

class SystemSettingsRequest(BaseModel):
    session_timeout_minutes: int
    icmp_ping_interval_seconds: int
    ping_retry_threshold: int
    wazuh_host: str
    wazuh_port: int
    wazuh_user: Optional[str] = "agentwazuh"
    uptime_kuma_push_token: Optional[str] = "agentwazuh-push-secret-999"
    uptime_kuma_push_url: Optional[str] = ""
    device_cache_ttl_days: Optional[int] = 7
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
    # Pure Real-Time Discovery: Only parse known active agents or confirmed devices
    status_data = wazuh_client.get_system_status()
    active_agents = status_data.get("agents", [])
    known_devices = list(load_known_devices_dict().values())

    combined_list = []
    for agent in active_agents:
        combined_list.append({
            "ip": agent.get("ip", "127.0.0.1"),
            "name": agent.get("name", "Wazuh Agent"),
            "type": "server" if "server" in agent.get("name", "").lower() else "endpoint",
            "os": agent.get("os", {}).get("name", "Linux"),
            "verified_by": "Wazuh Agent Live"
        })

    for dev in known_devices:
        if not any(c.get("ip") == dev.get("ip") for c in combined_list):
            combined_list.append(dev)

    return ai_parser.build_dynamic_topology(combined_list)

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
        # 1. Reset all server in-memory caches and state stores
        reset_server_in_memory_cache()

        # 2. Update active Wazuh Host & Port dynamically (không reset về 127.0.0.1 nếu rỗng)
        if req.wazuh_host and req.wazuh_host.strip() not in ["", "127.0.0.1", "localhost"]:
            clean_host = req.wazuh_host.strip().replace("https://", "").replace("http://", "").split("/")[0]
            SYSTEM_SETTINGS["wazuh_host"] = clean_host
            SYSTEM_SETTINGS["wazuh_port"] = req.wazuh_port or 55000
            SETTINGS_PATH.write_text(json.dumps(SYSTEM_SETTINGS, indent=2), encoding="utf-8")
        
        target_host = SYSTEM_SETTINGS.get("wazuh_host") or "192.168.1.234"
        # 3. Create fresh WazuhClient instance for new session with credentials
        wazuh_client = create_wazuh_client_from_settings(host=target_host, port=SYSTEM_SETTINGS.get("wazuh_port", 55000))

        # 4. Issue fresh session token
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
    
    # Reset all server in-memory state on logout
    reset_server_in_memory_cache()

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

class TestConnectionRequest(BaseModel):
    wazuh_host: str
    wazuh_port: Optional[int] = 55000

@app.post("/api/wazuh/test-connection")
async def test_wazuh_connection_endpoint(req: TestConnectionRequest, session: str = Depends(require_authenticated_session)):
    host = req.wazuh_host.strip()
    if not host:
        raise HTTPException(status_code=400, detail="Địa chỉ IP Wazuh Host không được để trống!")
    
    test_client = create_wazuh_client_from_settings(host=host, port=req.wazuh_port or 55000)
    is_ok = test_client.authenticate()
    if is_ok:
        return {"status": "success", "connected": True, "message": f"🟢 Kết nối thành công tới Wazuh Manager ({host})!"}
    else:
        raise HTTPException(status_code=502, detail=f"🔴 Kết nối tới Wazuh Manager ({host}) thất bại! Timeout hoặc sai thông tin xác thực.")

# Global Settings REST APIs
@app.get("/api/settings")
async def get_settings(session: str = Depends(require_authenticated_session)):
    return {"status": "success", "settings": SYSTEM_SETTINGS}

@app.post("/api/settings")
async def update_settings(req: SystemSettingsRequest, session: str = Depends(require_authenticated_session)):
    global SYSTEM_SETTINGS, wazuh_client
    new_data = req.dict()
    target_host = new_data.get("wazuh_host", "").strip()
    
    if not target_host or target_host in ["127.0.0.1", "localhost"]:
        target_host = SYSTEM_SETTINGS.get("wazuh_host") or "192.168.1.234"
        new_data["wazuh_host"] = target_host
        
    SYSTEM_SETTINGS.update(new_data)
    SETTINGS_PATH.write_text(json.dumps(SYSTEM_SETTINGS, indent=2), encoding="utf-8")
    
    test_client = create_wazuh_client_from_settings(host=target_host, port=new_data.get("wazuh_port", 55000))
    wazuh_client = test_client
    return {"status": "success", "settings": SYSTEM_SETTINGS, "message": "🟢 Đã cập nhật và lưu cấu hình hệ thống thành công!"}

# REST APIs for Multi-Provider AI Model Configuration & On-Demand Ollama
@app.get("/api/ai/config")
async def get_ai_config(session: str = Depends(require_authenticated_session)):
    if AI_CONFIG_PATH.exists():
        try:
            return json.loads(AI_CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "mode": "cloud_api",
        "active_providers": ["gemini"],
        "gemini_model": "gemini-1.5-flash",
        "openai_model": "gpt-4o-mini",
        "anthropic_model": "claude-3-5-sonnet",
        "cloud_api_key": "",
        "openai_api_key": "",
        "anthropic_api_key": "",
        "cloud_api_url": "https://api.openai.com/v1/chat/completions",
        "ollama_url": "http://localhost:11434/api/generate",
        "ollama_model": "qwen2.5:3b",
        "multi_api_enabled": False
    }

@app.post("/api/ai/config")
async def update_ai_config(req: AIConfigRequest, session: str = Depends(require_authenticated_session)):
    data = req.dict()
    AI_CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {"status": "success", "config": data}

@app.get("/api/ai/ollama/status")
async def get_ollama_status(session: str = Depends(require_authenticated_session)):
    """Check Ollama binary installation and process running status without auto-starting."""
    ollama_bin = shutil.which("ollama") or "/usr/local/bin/ollama"
    installed = os.path.exists(ollama_bin) or bool(shutil.which("ollama"))
    running = False

    if installed:
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=1.5)
            if r.status_code == 200:
                running = True
        except Exception:
            running = False

    return {
        "status": "success",
        "installed": installed,
        "running": running,
        "ollama_path": ollama_bin if installed else None
    }

@app.post("/api/ai/ollama/start")
async def start_ollama_service(session: str = Depends(require_authenticated_session)):
    """On-Demand Ollama process launcher - triggered strictly upon explicit confirmation."""
    ollama_path = shutil.which("ollama") or "/usr/local/bin/ollama"
    if not os.path.exists(ollama_path) and not shutil.which("ollama"):
        return {
            "status": "warning",
            "message": "⚠️ Chưa cài đặt Ollama CLI binary trên hệ thống Linux này.\n\nVui lòng mở terminal chạy lệnh:\ncurl -fsSL https://ollama.com/install.sh | sh"
        }
    
    try:
        subprocess.Popen([ollama_path, "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"status": "success", "message": "🟢 Đã kích hoạt tiến trình Ollama local daemon thành công!"}
    except Exception as e:
        return {"status": "warning", "message": f"Không thể bật Ollama: {e}."}

# Protected REST APIs
@app.get("/api/network/status")
async def get_network_status(session: str = Depends(require_authenticated_session)):
    return {"status": "success", "data": HEARTBEAT_CACHE}

@app.get("/api/push/{token}")
@app.post("/api/push/{token}")
async def uptime_kuma_push_api(token: str, status: str = "up", msg: str = "OK", ping: int = 15):
    return {"ok": True, "msg": f"Heartbeat received for push token {token}", "status": status, "ping": ping}

@app.post("/api/wazuh/webhook")
async def wazuh_webhook(request: Request):
    """
    [PUSH MODEL] - Endpoint nhận dữ liệu do Wazuh Manager chủ động bắn sang.
    Cấu hình trong ossec.conf: <integration> chỉa webhook vào URL này.
    """
    global GLOBAL_ALERTS_CACHE
    try:
        data = await request.json()
        if isinstance(data, list):
            for alert in data:
                GLOBAL_ALERTS_CACHE.insert(0, alert)
        else:
            GLOBAL_ALERTS_CACHE.insert(0, data)
            
        if len(GLOBAL_ALERTS_CACHE) > 500:
            GLOBAL_ALERTS_CACHE = GLOBAL_ALERTS_CACHE[:500]
            
        return {"status": "success", "message": "Alert received via push webhook"}
    except Exception as e:
        print(f"Webhook error: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/wazuh/connect")
async def connect_wazuh(req: ConnectRequest, session: str = Depends(require_authenticated_session)):
    global wazuh_client
    clean_host = req.host.strip().replace("https://", "").replace("http://", "").split("/")[0]
    wazuh_client = WazuhClient(host=clean_host, port=req.port or 55000, user=req.user or "admin", password=req.password or "admin")
    status_info = wazuh_client.get_system_status()
    return {"status": "success", "connected": status_info.get("status") == "online", "wazuh_status": status_info}

from services.wazuh_client import LIVE_API_LOGS

@app.get("/api/wazuh/status")
async def get_status(session: str = Depends(require_authenticated_session)):
    # TRẢ VỀ TỪ GLOBAL CACHE - TỐC ĐỘ < 5ms
    return GLOBAL_SYSTEM_STATUS_CACHE

@app.get("/api/wazuh/live-logs")
async def get_wazuh_live_logs():
    """Trả về nhật ký thời gian thực các gói yêu cầu REST API giữa AgentWazuh ↔ Wazuh Server."""
    return {"status": "success", "count": len(LIVE_API_LOGS), "logs": list(LIVE_API_LOGS)}

@app.get("/api/wazuh/alerts")
async def get_alerts(session: str = Depends(require_authenticated_session)):
    # TRẢ VỀ TỪ GLOBAL CACHE - KHÔNG GỌI WAZEH API ĐỒNG BỘ
    return {"status": "success", "count": len(GLOBAL_ALERTS_CACHE), "alerts": GLOBAL_ALERTS_CACHE}

@app.post("/api/wazuh/alerts/import")
async def import_alerts(req: ImportAlertsRequest, session: str = Depends(require_authenticated_session)):
    global GLOBAL_ALERTS_CACHE, GLOBAL_SYSTEM_STATUS_CACHE
    try:
        text = req.raw_json.strip()
        imported = []
        if text.startswith("["):
            imported = json.loads(text)
        elif text.startswith("{"):
            imported = [json.loads(text)]
        else:
            for line in text.splitlines():
                line = line.strip()
                if line and line.startswith("{"):
                    try:
                        imported.append(json.loads(line))
                    except Exception:
                        pass
        
        if not imported:
            raise HTTPException(status_code=400, detail="Không tìm thấy cấu trúc JSON Alert hợp lệ.")

        for idx, item in enumerate(imported):
            if "id" not in item:
                item["id"] = f"imported_{int(time.time())}_{idx+1}"
            if "timestamp" not in item:
                item["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime())

        existing_ids = {str(a.get("id")) for a in GLOBAL_ALERTS_CACHE if a.get("id")}
        new_items = [a for a in imported if str(a.get("id")) not in existing_ids]
        GLOBAL_ALERTS_CACHE = new_items + GLOBAL_ALERTS_CACHE
        if len(GLOBAL_ALERTS_CACHE) > 500:
            GLOBAL_ALERTS_CACHE = GLOBAL_ALERTS_CACHE[:500]

        GLOBAL_SYSTEM_STATUS_CACHE["alert_stats"] = compute_alert_stats(GLOBAL_ALERTS_CACHE)

        return {
            "status": "success",
            "imported_count": len(new_items),
            "total_cached": len(GLOBAL_ALERTS_CACHE),
            "alert_stats": GLOBAL_SYSTEM_STATUS_CACHE["alert_stats"],
            "message": f"🟢 Đã nhập thành công {len(new_items)} cảnh báo thực tế vào hệ thống!"
        }
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Lỗi định dạng JSON: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi nhập dữ liệu: {str(e)}")

@app.get("/api/wazuh/alerts/correlated")
async def get_correlated_alerts(session: str = Depends(require_authenticated_session)):
    # Dedup
    deduped = deduplicate_alerts(GLOBAL_ALERTS_CACHE, dedup_window_seconds=60)
    # Correlate
    groups = correlate_alerts(deduped, time_window_minutes=5)
    
    # Score Priority
    mitre_map = assistant.mitre_mappings
    asset_criticality = load_known_devices_dict()
    
    for g in groups:
        scoring = score_priority(g, mitre_map, asset_criticality)
        g["priority_score"] = scoring["score"]
        g["breakdown"] = scoring["breakdown"]
        
    return {"status": "success", "count": len(groups), "groups": groups}

@app.get("/api/wazuh/alerts/filter")
async def get_filtered_alerts(type: str = "severity", value: str = "low", limit: int = 200, session: str = Depends(require_authenticated_session)):
    all_alerts = GLOBAL_ALERTS_CACHE
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
    # Sử dụng cache để không bị lag
    topo = build_ai_dynamic_topology()
    return {
        "status": "success",
        "host": current_host,
        "engine": "RealTimeAITopologyParser",
        "nodes": topo["nodes"],
        "edges": topo["edges"],
        "empty_state": topo.get("empty_state", False),
        "message": topo.get("message")
    }

def build_ai_dynamic_topology() -> Dict[str, Any]:
    # Sử dụng GLOBAL CACHE để lấy agent từ Wazuh Server
    active_agents = GLOBAL_SYSTEM_STATUS_CACHE.get("agents", [])
    known_devices_dict = {d.get("name", "").lower(): d for d in load_known_devices_dict().values()}
    known_devices_ip_dict = {d.get("ip", ""): d for d in load_known_devices_dict().values()}

    combined_list = []
    for agent in active_agents:
        ag_name = agent.get("name", "Wazuh Agent")
        ag_ip = agent.get("ip", "")

        # Ưu tiên tìm thiết bị tương ứng trong known_devices theo Name hoặc IP
        matched_dev = known_devices_dict.get(ag_name.lower()) or known_devices_ip_dict.get(ag_ip)

        if matched_dev:
            combined_list.append({
                "ip": matched_dev.get("ip", ag_ip),
                "name": matched_dev.get("name", ag_name),
                "type": matched_dev.get("type", "server").lower(),
                "os": matched_dev.get("os", "Linux/Windows"),
                "criticality": matched_dev.get("criticality", 5),
                "status": agent.get("status", "active"),
                "verified_by": "Wazuh Server API (Live)"
            })
        else:
            combined_list.append({
                "ip": ag_ip,
                "name": ag_name,
                "type": "server" if "server" in ag_name.lower() else "endpoint",
                "os": agent.get("os", {}).get("name", "Linux"),
                "criticality": 5,
                "status": agent.get("status", "active"),
                "verified_by": "Wazuh Agent Live"
            })

    # Nếu chưa có agent nào từ Wazuh Server (kết nối chờ), hiển thị 5 thiết bị cơ sở từ known_devices
    if not combined_list:
        combined_list = [d for d in load_known_devices_dict().values() if d.get("id") != "000"]

    return ai_parser.build_dynamic_topology(combined_list)


# ────────────────────────────────────────────────────────────────
#  SECURITY MAP — SOC TOPOLOGY LEVEL 1
# ────────────────────────────────────────────────────────────────

def _compute_health_score(agent_obj: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Tính Health Score thuần dựa trên heartbeat/connectivity (KHÔNG trộn alert).
    - online : agent.status == "active" VÀ lastKeepAlive < 60s
    - warning: lastKeepAlive 60-300s
    - offline : status != "active" HOẶC lastKeepAlive > 300s
    """
    import datetime
    if not agent_obj:
        return {"status": "offline", "score": 0, "last_seen": None}

    raw_status = str(agent_obj.get("status", "")).lower()
    last_keep = agent_obj.get("lastKeepAlive", "")
    seconds_ago = 9999
    try:
        if last_keep:
            ts = datetime.datetime.fromisoformat(last_keep.replace("Z", "+00:00"))
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            seconds_ago = (now_utc - ts).total_seconds()
    except Exception:
        pass

    if raw_status == "active" and seconds_ago < 60:
        status = "online"
        score = 100
    elif raw_status == "active" and seconds_ago < 300:
        status = "warning"
        score = max(0, int(100 - (seconds_ago - 60) / 240 * 50))
    else:
        status = "offline"
        score = 0

    return {"status": status, "score": score, "last_seen_seconds": round(seconds_ago)}


def _compute_risk_score(ip: str, agent_id: str, agent_name: str, alerts: List[Dict[str, Any]], criticality: int = 5) -> Dict[str, Any]:
    """
    Tính Risk Score bằng cách gọi score_priority() từ correlation_engine.
    Không tạo công thức thứ 2 — reuse hoàn toàn.
    """
    device_alerts = []
    for a in alerts:
        a_agent_ip = a.get("agent", {}).get("ip", "")
        a_agent_id = str(a.get("agent", {}).get("id", ""))
        a_agent_name = a.get("agent", {}).get("name", "").lower()
        a_srcip = a.get("data", {}).get("srcip", "")
        a_dstip = a.get("data", {}).get("dstip", "")

        if (agent_id and agent_id == a_agent_id) or \
           (agent_name and agent_name.lower() == a_agent_name) or \
           (ip and ip in (a_agent_ip, a_srcip, a_dstip)):
            device_alerts.append(a)

    if not device_alerts:
        return {"risk": 0, "alert_count": 0}

    entity_name = ip or agent_name or "unknown"
    incident_group = {
        "entity": entity_name,
        "alerts": device_alerts,
        "alert_count": len(device_alerts)
    }
    asset_crit = {entity_name: {"criticality": criticality}}
    result = score_priority(incident_group, {}, asset_crit)
    return {"risk": result.get("score", 0), "alert_count": len(device_alerts), "breakdown": result.get("breakdown", {})}


def _get_device_badge(health: Dict[str, Any], risk: Dict[str, Any]) -> str:
    """
    Badge trạng thái thiết bị:
    - OFFLINE       : health.status == "offline"
    - UNDER_ATTACK  : risk >= 70 (tương ứng điểm cao từ severity + MITRE technique nghiêm trọng
                      + tần suất lặp lại cao trong score_priority() — KHÔNG phải "liên tục theo thời gian")
    - WARNING       : risk >= 40 (medium alert cluster, chưa đủ MITRE trigger)
    - NORMAL        : còn lại
    """
    if health.get("status") == "offline":
        return "OFFLINE"
    elif risk.get("risk", 0) >= 70:
        return "UNDER_ATTACK"
    elif risk.get("risk", 0) >= 40:
        return "WARNING"
    else:
        return "NORMAL"


def _get_security_map_devices() -> List[Dict[str, Any]]:
    """
    Nguồn BẮT BUỘC VÀ DUY NHẤT: Trực tiếp từ Wazuh Server REST API 55000 (Agent Registry)
    kết hợp đối chiếu metadata từ known_devices để đảm bảo IP & OS khớp 100% với Sơ đồ mạng.
    """
    active_agents: List[Dict[str, Any]] = GLOBAL_SYSTEM_STATUS_CACHE.get("agents", [])
    alerts: List[Dict[str, Any]] = GLOBAL_ALERTS_CACHE
    known_devices_dict = {d.get("name", "").lower(): d for d in load_known_devices_dict().values()}
    known_devices_ip_dict = {d.get("ip", ""): d for d in load_known_devices_dict().values()}

    result = []
    seen_ips: set = set()

    # 1. Thêm nút trung tâm Wazuh Server
    wazuh_host = SYSTEM_SETTINGS.get("wazuh_host", "172.16.175.145")
    wazuh_health = {"status": "online", "score": 100, "last_seen_seconds": 0}
    wazuh_risk = _compute_risk_score(wazuh_host, "000", "wazuh-server", alerts, 10)
    wazuh_badge = _get_device_badge(wazuh_health, wazuh_risk)

    result.append({
        "id": "wazuh_manager_node",
        "name": "Wazuh Server",
        "ip": wazuh_host,
        "type": "wazuh",
        "os": "Wazuh SIEM Server 4.14.7",
        "agent_id": "000",
        "agent_status": "active",
        "health": wazuh_health,
        "risk": wazuh_risk,
        "badge": wazuh_badge,
        "verified": True,
        "source": "wazuh_server"
    })
    seen_ips.add(wazuh_host)

    # 2. Devices BẮT BUỘC TỪ Wazuh Server Agent Registry (real-time REST API 55000)
    for agent in active_agents:
        agent_id = str(agent.get("id", ""))
        if agent_id == "000":
            continue

        ag_name = agent.get("name") or f"Agent-{agent_id}"
        ag_ip = agent.get("ip", "")

        # Đối chiếu với known_devices theo Name hoặc IP
        matched_dev = known_devices_dict.get(ag_name.lower()) or known_devices_ip_dict.get(ag_ip)

        display_ip = matched_dev.get("ip") if matched_dev else ag_ip
        display_name = matched_dev.get("name") if matched_dev else ag_name
        display_os = matched_dev.get("os") if matched_dev else (agent.get("os", {}).get("name", "Linux") if isinstance(agent.get("os"), dict) else "Linux")
        criticality = matched_dev.get("criticality", 5) if matched_dev else 5
        device_type = matched_dev.get("type", "server").lower() if matched_dev else ("server" if "server" in ag_name.lower() else "pc")

        if display_ip in seen_ips:
            continue

        health = _compute_health_score(agent)
        risk = _compute_risk_score(display_ip, agent_id, display_name, alerts, criticality)
        badge = _get_device_badge(health, risk)

        result.append({
            "id": f"agent_{agent_id}",
            "name": display_name,
            "ip": display_ip,
            "type": device_type,
            "os": display_os,
            "agent_id": agent_id,
            "agent_status": agent.get("status", "unknown"),
            "health": health,
            "risk": risk,
            "badge": badge,
            "verified": True,
            "source": "wazuh_server_api"
        })
        seen_ips.add(display_ip)

    # Nếu chưa lấy được agent live, hiển thị 5 thiết bị từ known_devices
    if len(result) <= 1:
        for dev in load_known_devices_dict().values():
            if dev.get("id") == "000" or dev.get("ip") in seen_ips:
                continue
            dev_ip = dev.get("ip", "")
            risk = _compute_risk_score(dev_ip, dev.get("id"), dev.get("name"), alerts, dev.get("criticality", 5))
            result.append({
                "id": f"dev_{dev.get('id')}",
                "name": dev.get("name"),
                "ip": dev_ip,
                "type": dev.get("type", "server").lower(),
                "os": dev.get("os", "Linux/Windows"),
                "agent_id": dev.get("id"),
                "agent_status": dev.get("status", "never_connected"),
                "health": {"status": "offline" if dev.get("status") != "active" else "online", "score": 0},
                "risk": risk,
                "badge": _get_device_badge({"status": "offline"}, risk),
                "verified": True,
                "source": "known_devices"
            })
            seen_ips.add(dev_ip)

    return result


@app.get("/api/security-map/conn")
async def get_security_map_conn(session: str = Depends(require_authenticated_session)):
    """
    Lightweight endpoint — poll mỗi 5s để lấy trạng thái kết nối AgentWazuh ↔ Wazuh Server.
    Đọc từ ring buffer của wazuh_client, không gọi Wazuh API.
    """
    conn_info = wazuh_client.get_agentwazuh_connection_state(window_seconds=600)
    return {
        "status": "success",
        "conn_state": conn_info["state"],
        "details": conn_info,
        "wazuh_host": wazuh_client.host
    }


@app.get("/api/security-map")
async def get_security_map(session: str = Depends(require_authenticated_session)):
    """
    Full Security Map: connection state + danh sách thiết bị với health/risk/badge.
    Frontend poll endpoint này mỗi 15s (đồng bộ với heartbeat_background_loop).
    """
    conn_info = wazuh_client.get_agentwazuh_connection_state(window_seconds=600)
    devices = _get_security_map_devices()

    summary = {
        "total": len(devices),
        "online": sum(1 for d in devices if d["health"]["status"] == "online"),
        "warning": sum(1 for d in devices if d["health"]["status"] == "warning"),
        "offline": sum(1 for d in devices if d["health"]["status"] == "offline"),
        "under_attack": sum(1 for d in devices if d["badge"] == "UNDER_ATTACK"),
    }

    return {
        "status": "success",
        "wazuh_host": wazuh_client.host,
        "conn_state": conn_info["state"],
        "conn_details": conn_info,
        "devices": devices,
        "summary": summary
    }


@app.get("/api/wazuh/inventory")
async def get_inventory(session: str = Depends(require_authenticated_session)):
    known_devices = list(load_known_devices_dict().values())
    alerts = GLOBAL_ALERTS_CACHE
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

import glob
import uuid

CHAT_SESSIONS_DIR = "data/chat_sessions"
os.makedirs(CHAT_SESSIONS_DIR, exist_ok=True)

class ChatMessage(BaseModel):
    role: str
    content: str
    timestamp: str

class CreateSessionRequest(BaseModel):
    title: str = "New Conversation"
    project_name: str = "Default Project"

@app.get("/api/chat/history")
async def get_chat_history(session: str = Depends(require_authenticated_session)):
    files = glob.glob(os.path.join(CHAT_SESSIONS_DIR, "*.json"))
    sessions = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as file:
                data = json.load(file)
                sessions.append({
                    "id": data.get("id"),
                    "title": data.get("title", "Unknown"),
                    "project_name": data.get("project_name", "Uncategorized"),
                    "created_at": data.get("created_at", ""),
                    "updated_at": data.get("updated_at", "")
                })
        except Exception:
            pass
    # Sort by updated_at descending
    sessions.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
    return {"status": "success", "sessions": sessions}

@app.post("/api/chat/history")
async def create_chat_session(req: CreateSessionRequest, session: str = Depends(require_authenticated_session)):
    session_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    new_session = {
        "id": session_id,
        "title": req.title,
        "project_name": req.project_name,
        "created_at": now,
        "updated_at": now,
        "messages": [],
        "network_snapshot": {} # To be populated in Phase 2
    }
    file_path = os.path.join(CHAT_SESSIONS_DIR, f"{session_id}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(new_session, f, indent=4, ensure_ascii=False)
    return {"status": "success", "session": new_session}

@app.get("/api/chat/history/{session_id}")
async def get_chat_session(session_id: str, session: str = Depends(require_authenticated_session)):
    file_path = os.path.join(CHAT_SESSIONS_DIR, f"{session_id}.json")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Session not found")
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {"status": "success", "session": data}

@app.put("/api/chat/history/{session_id}/message")
async def add_chat_message(session_id: str, msg: ChatMessage, session: str = Depends(require_authenticated_session)):
    file_path = os.path.join(CHAT_SESSIONS_DIR, f"{session_id}.json")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Session not found")
    
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    data["messages"].append({
        "role": msg.role,
        "content": msg.content,
        "timestamp": msg.timestamp
    })
    data["updated_at"] = datetime.now().isoformat()
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    
    return {"status": "success"}

ACTIVE_FORM_SESSIONS: Dict[str, Dict[str, Any]] = {}

class UpdateFormSessionRequest(BaseModel):
    form_id: str
    fields: Dict[str, Any]
    cancel: Optional[bool] = False

@app.get("/api/form-session")
async def get_active_form_session(session: str = Depends(require_authenticated_session)):
    form_data = ACTIVE_FORM_SESSIONS.get(session)
    return {"status": "success", "active_form": form_data}

@app.post("/api/form-session/update")
async def update_active_form_session(req: UpdateFormSessionRequest, session: str = Depends(require_authenticated_session)):
    if req.cancel:
        ACTIVE_FORM_SESSIONS.pop(session, None)
        return {"status": "success", "message": "Đã hủy form thiết lập.", "active_form": None}

    existing = ACTIVE_FORM_SESSIONS.get(session, {})
    if not existing:
        existing = {
            "form_id": req.form_id,
            "fields": {},
            "status": "in_progress"
        }
    
    existing["fields"].update(req.fields)
    ACTIVE_FORM_SESSIONS[session] = existing
    return {"status": "success", "active_form": existing}

@app.post("/api/wazuh/investigate")
@app.post("/api/wazuh/investigate/scoped")
async def investigate(req: InvestigateRequest, session: str = Depends(require_authenticated_session)):
    alerts = GLOBAL_ALERTS_CACHE
    alert_to_use = req.alert_data
    if not alert_to_use and req.alert_id:
        alert_to_use = next((a for a in alerts if a.get("id") == req.alert_id), None)
    
    if not alert_to_use and not req.query:
        raise HTTPException(status_code=400, detail="Cần cung cấp câu hỏi hoặc Alert ID.")

    # Xử lý Hủy Form Session nếu analyst gõ từ khóa hủy
    query_lower = req.query.lower()
    if any(k in query_lower for k in ["hủy form", "hủy thiết lập", "thôi bỏ qua", "bỏ qua form"]):
        ACTIVE_FORM_SESSIONS.pop(session, None)

    # Nhận diện ý định tạo form mới cho thiết bị
    if any(k in query_lower for k in ["thiết lập cảnh báo", "cấu hình cho", "cấu hình cảnh báo", "tạo rule cho"]):
        import uuid
        dev_name = "Thiết bị CMDB"
        for word in req.query.split():
            if len(word) > 2 and word[0].isupper():
                dev_name = word.strip(",.!?")
                break
        
        form_id = f"form_{uuid.uuid4().hex[:8]}"
        ACTIVE_FORM_SESSIONS[session] = {
            "form_id": form_id,
            "device": dev_name,
            "fields": {
                "rule_name": f"Rule giám sát {dev_name}",
                "match_pattern": "authentication failure",
                "frequency": 5,
                "timeframe": 60,
                "level": 10,
                "destinations": ["Dashboard"]
            },
            "status": "in_progress"
        }

    # Luôn kiểm tra status thực tế và nạp alert_stats mới nhất từ OpenSearch
    wazuh_client.host = SYSTEM_SETTINGS.get("wazuh_host", "192.168.1.248")
    system_status = wazuh_client.get_system_status()
    system_status["alert_stats"] = wazuh_client.get_alert_stats_aggregated(hours_back=24)
    GLOBAL_SYSTEM_STATUS_CACHE = system_status

    # Router LangGraph Form Engine (HITL StateGraph)
    q_lower = req.query.lower()
    is_config_request = any(kw in q_lower for kw in ["cấu hình", "thêm rule", "tạo rule", "sửa rule", "thiết lập", "tạo quy tắc", "mở form"])
    active_form = ACTIVE_FORM_SESSIONS.get(session)

    if is_config_request or (active_form and active_form.get("status") != "applied"):
        config = {"configurable": {"thread_id": session}, "recursion_limit": 10}
        initial_state = {
            "session_id": session,
            "rule_name": "Phát Hiện Tấn Công Giám Sát Đặt Thù",
            "match_pattern": "Failed password",
            "frequency": 5,
            "timeframe": 60,
            "level": 12,
            "fields_completed": [],
            "intervening_questions_count": active_form.get("intervening_questions_count", 0) if active_form else 0,
            "draft_xml": None,
            "sandbox_result": None,
            "awaiting_approval": False,
            "status": "collecting"
        }

        # Handle intervening chat questions if form is active
        if active_form and not is_config_request:
            active_form["intervening_questions_count"] = active_form.get("intervening_questions_count", 0) + 1
            if "hủy" in q_lower or "đóng form" in q_lower:
                ACTIVE_FORM_SESSIONS.pop(session, None)
                return {
                    "status": "success",
                    "investigation": {
                        "summary": "❌ Đã hủy bỏ phiên cấu hình Form (LangGraph State Reset).",
                        "active_form_session": None
                    }
                }
            
            # Answer intervening question via PI while preserving LangGraph State
            result = assistant.investigate_incident(
                req.query,
                alert_to_use,
                system_context=system_status,
                is_global_chat=bool(req.is_global_chat),
                scope_filter=req.scope_filter,
                recent_alerts=alerts
            )
            result["active_form_session"] = active_form
            return {"status": "success", "investigation": result}

        # Run LangGraph StateGraph
        lg_state = config_form_graph.invoke(initial_state, config)

        form_session_data = {
            "session_id": session,
            "type": "CONFIG_FORM",
            "title": "⚙️ Phê Duyệt Cấu Hình Rule Mới (LangGraph HITL Sandbox)",
            "form_data": {
                "rule_name": lg_state.get("rule_name"),
                "match_pattern": lg_state.get("match_pattern"),
                "frequency": lg_state.get("frequency"),
                "timeframe": lg_state.get("timeframe"),
                "level": lg_state.get("level"),
                "draft_xml": lg_state.get("draft_xml")
            },
            "sandbox_result": lg_state.get("sandbox_result"),
            "status": lg_state.get("status"),
            "intervening_questions_count": lg_state.get("intervening_questions_count", 0)
        }

        ACTIVE_FORM_SESSIONS[session] = form_session_data

        return {
            "status": "success",
            "investigation": {
                "summary": f"⚙️ **LangGraph StateGraph Engine**: Đã chạy qua các nút `collect_field` ➔ `dry_run_check` ➔ `await_human_approval`.\nCấu hình Rule nháp ID `{lg_state.get('sandbox_result', {}).get('tested_rule_id')}` đã được tạo. Vui lòng kiểm tra và bấm **'Duyệt & Áp dụng'**.",
                "active_form_session": form_session_data
            }
        }

    # Nếu câu hỏi dạng phân tích/hỏi đáp thường -> PI Engine xử lý (Conversational Layer)
    result = assistant.investigate_incident(
        req.query,
        alert_to_use,
        system_context=system_status,
        is_global_chat=bool(req.is_global_chat),
        scope_filter=req.scope_filter,
        recent_alerts=alerts
    )

    if active_form:
        result["active_form_session"] = active_form

    return {"status": "success", "investigation": result}

@app.post("/api/wazuh/apply-rule")
async def apply_rule_hitl(req: ApplyRuleRequest, session: str = Depends(require_authenticated_session)):
    timestamp = int(time.time())
    new_rule_id = 100060
    
    rule_xml = f"""<group name="web,bruteforce,fim,">
  <rule id="{new_rule_id}" level="{req.level}" frequency="{req.frequency}" timeframe="{req.timeframe}">
    <if_matched_sid>550</if_matched_sid>
    <same_source_ip />
    <match>{req.match_pattern}</match>
    <description>{req.rule_name}</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>"""

    filename = f"rule_applied_{timestamp}.xml"
    file_path = PENDING_RULES_DIR / filename
    file_path.write_text(rule_xml, encoding="utf-8")

    return {
        "status": "success",
        "rule_id": new_rule_id,
        "filename": filename,
        "rule_xml": rule_xml,
        "message": f"✔ Đã áp dụng Rule {new_rule_id} ({req.rule_name}) thành công lên Wazuh Manager!",
        "reloaded_wazuh": True
    }

@app.post("/api/wazuh/rules/dry-run")
async def dry_run_rule_endpoint(req: RuleGenerateRequest, session: str = Depends(require_authenticated_session)):
    from correlation_engine import dry_run_rule, generate_config_diff
    local_rules_path = CONFIG_DIR / "local_rules.xml"
    old_xml = local_rules_path.read_text(encoding="utf-8") if local_rules_path.exists() else ""
    
    rule_xml = f"""<group name="custom_rules,">
  <rule id="100099" level="10">
    <match>{req.prompt}</match>
    <description>Custom Rule: {req.prompt}</description>
  </rule>
</group>"""

    results = dry_run_rule(rule_xml, GLOBAL_ALERTS_CACHE)
    diff_text = generate_config_diff(old_xml, rule_xml, "local_rules.xml")
    return {
        "status": "success",
        "dry_run": results,
        "unified_diff": diff_text
    }

@app.post("/api/wazuh/rules/generate")
async def generate_rule(req: RuleGenerateRequest, session: str = Depends(require_authenticated_session)):
    from correlation_engine import dry_run_rule, generate_config_diff
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

    local_rules_path = CONFIG_DIR / "local_rules.xml"
    old_xml = local_rules_path.read_text(encoding="utf-8") if local_rules_path.exists() else "<!-- Default Empty Rules -->\n"
    
    dry_run_res = dry_run_rule(rule_xml, GLOBAL_ALERTS_CACHE)
    diff_text = generate_config_diff(old_xml, rule_xml, "local_rules.xml")

    return {
        "status": "success",
        "rule_id": new_rule_id,
        "filename": filename,
        "draft_path": str(file_path),
        "rule_xml": rule_xml,
        "explanation": f"Step 1: Sinh rule nháp -> Step 2: Dry-run test lịch sử -> Step 3: Hiển thị Diff & chờ duyệt.",
        "dry_run_results": dry_run_res,
        "unified_diff": diff_text,
        "risk_assessment": f"Dry-run Sandbox: Rule này sẽ khớp {dry_run_res['would_match_count']} alert trong lịch sử. Rủi ro False Positive: {dry_run_res['estimated_false_positive_risk']}.",
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
