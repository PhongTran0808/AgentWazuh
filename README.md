# 🛡️ AGENT WAZUH — SOC AI ASSISTANT & SECURITY CO-PILOT SYSTEM

**Version:** 14.0.0 · **Backend:** FastAPI · **AI orchestration:** LangGraph + MCP

AgentWazuh là hệ thống SOC AI Co-Pilot kết nối với Wazuh SIEM Manager để thu thập và phân tích cảnh báo, tương quan sự kiện, chấm điểm rủi ro, điều tra sự cố và đề xuất hành động ứng phó có kiểm soát bởi operator.

> **Lưu ý bảo mật:** Đây là hệ thống quản trị an ninh có khả năng thực hiện active response và thay đổi cấu hình Wazuh. Chỉ chạy trong môi trường được cấp phép; không commit password, token, webhook hoặc dữ liệu evidence vào Git.

## ✨ Tính năng chính

- **Alert ingestion:** Lấy alerts, agents và manager status qua Wazuh REST API.
- **Correlation Engine:** Deduplication, gom nhóm theo entity/time window, NetworkX graph, TF-IDF similarity, confidence và priority scoring.
- **AI investigation:** Tạo context điều tra có grounding từ dữ liệu Wazuh và hỗ trợ provider/PI CLI hoặc Ollama.
- **Multi-agent workflow:** Log ingestion, device discovery, risk scoring, threat analysis và mitigation.
- **MCP integration:** Discover và gọi Wazuh tools qua Model Context Protocol.
- **HITL configuration workflow:** Draft, preview, validate và apply rule/config sau khi operator phê duyệt.
- **SoL-Pi evidence pipeline:** Lưu ObservationPack, hash receipt và audit trail cho mỗi investigation.
- **Topology dashboard:** Sinh network topology động từ thiết bị thực tế; không dùng topology giả khi không có dữ liệu.
- **Telegram và Discord:** Điều tra hai chiều qua Telegram; forward alert có `rule.level > 11` sang Discord.

## 🏗️ Kiến trúc

```text
Web UI (web/)
    │
    ▼
FastAPI Core (core/server.py :8080)
    │
    ├── WazuhClient ─────────────── Wazuh Manager REST API :55000
    ├── Correlation Engine
    ├── Incident Assistant / Ollama
    ├── SoL-Pi Evidence + Audit Logger
    ├── MCP Client ──────────────── Local Wazuh MCP :3000
    ├── LangGraph HITL workflows
    └── Telegram / Discord integrations

WazuhSim Network Map (server_9090.py :9090)
```

### Cổng dịch vụ

| Port | Dịch vụ |
|---:|---|
| `8080` | FastAPI Core, SOC dashboard và REST API |
| `9090` | Network Map & Live Streamer |
| `3000` | Local Wazuh MCP Server, chỉ bind `127.0.0.1` |
| `55000` | Wazuh Manager REST API |

## 📁 Cấu trúc repository

```text
AgentWazuh/
├── .pi/                                 # Prompt, policy, chains và MCP extension
├── core/server.py                       # FastAPI routes, auth, startup tasks
├── services/
│   ├── wazuh_client.py                  # JWT client, retry và Wazuh fallback
│   ├── correlation_engine.py            # Dedup, correlation, graph, scoring
│   ├── incident_assistant.py            # AI context và investigation
│   ├── solpi_wazuh.py                   # ObservationPack/evidence
│   ├── audit_logger.py                  # Audit trail
│   ├── ollama_client.py                 # Local LLM client
│   ├── telegram_bot.py                  # Telegram polling
│   └── discord_webhook.py               # Discord alert forwarding
├── integrations/
│   ├── wazuh_mcp_client.py              # MCP client
│   └── wazuh_config_manager.py          # Preview, validate, backup, apply config
├── mcp_layer/                           # Wazuh/correlation/case MCP tools
├── langgraph_engine/graphs/             # HITL StateGraph workflows
├── web/                                 # HTML, JavaScript, CSS dashboard
├── config/
│   ├── system_settings.json             # Wazuh connection settings
│   ├── known_devices.json               # Device inventory
│   └── pending_rules/                   # Draft rule changes
├── data/                                 # Runtime evidence, logs và backup (không commit)
├── reference/Wazuh-MCP-Server/          # Upstream MCP server
├── server.py                            # Entry point :8080
├── server_9090.py                       # Network map :9090
├── run_both_agentwazuh_services.py      # Launcher cho cả hai service
├── install_and_run.sh                   # Auto installer/launcher
└── requirements.txt                     # Python dependencies
```

## ⚙️ Yêu cầu

- Linux/macOS; Python **3.10+**, khuyến nghị **3.11+** cho MCP và LangGraph.
- Wazuh Manager 4.x với REST API có thể truy cập từ host chạy AgentWazuh.
- Kết nối tới Wazuh API `https://<wazuh-manager>:55000`.
- Nếu bật MCP local: Python virtualenv và systemd service `agentwazuh-mcp.service`.

## 🚀 Cài đặt và chạy

### Cách 1: Auto installer

```bash
git clone https://github.com/PhongTran0808/AgentWazuh.git
cd AgentWazuh
chmod +x install_and_run.sh
./install_and_run.sh
```

`install_and_run.sh` tự tìm Python phù hợp, cài `requirements.txt` và chạy Core Server trên port `8080`.

### Cách 2: Virtual environment thủ công

```bash
git clone https://github.com/PhongTran0808/AgentWazuh.git
cd AgentWazuh
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python server.py
```

Mở `http://localhost:8080`.

### Chạy cả Core và Network Map

```bash
python3 run_both_agentwazuh_services.py
```

- `http://localhost:8080`: SOC AI Assistant
- `http://localhost:9090`: Network Map & Live Streamer

## 🔐 Cấu hình và secrets

### `config/system_settings.json`

```json
{
  "wazuh_host": "192.168.1.201",
  "wazuh_port": 55000,
  "user": "wazuh",
  "password": "wazuh",
  "ping_interval": 15,
  "ping_retry": 3
}
```

Trong production, không lưu password trong JSON hoặc Git; dùng biến môi trường/runtime secret. Ví dụ `pass.env` phải được git-ignore:

```bash
WAZUH_HOST="192.168.1.201"
WAZUH_PORT="55000"
WAZUH_USER="wazuh"
WAZUH_PASSWORD="<strong-password>"

# Optional integrations
TELEGRAM_BOT_TOKEN="<telegram-token>"
TELEGRAM_ALLOWED_CHAT_IDS="123456789"
DISCORD_WEBHOOK_URL="<discord-webhook-url>"
OLLAMA_HOST="http://127.0.0.1:11434"
SESSION_SECRET_KEY="<random-secret>"
```

### Telegram

```bash
export TELEGRAM_BOT_TOKEN='<token>'
export TELEGRAM_ALLOWED_CHAT_IDS='123456789'
python3 server.py
```

Bot tự polling khi Core khởi động. Gửi `/start` hoặc câu hỏi điều tra tự nhiên.

### Discord

```bash
export DISCORD_WEBHOOK_URL='<webhook-url>'
python3 server.py
```

Các alert có `rule.level > 11` được forward dưới dạng Discord Embed; alert trùng được deduplicate theo alert ID.

## 🔌 Wazuh MCP Server

MCP server upstream chạy native bằng Python virtualenv, không dùng Docker, và chỉ bind local:

```bash
systemctl status agentwazuh-mcp.service
systemctl restart agentwazuh-mcp.service
curl http://127.0.0.1:3000/health
```

Credential đặt tại `reference/Wazuh-MCP-Server/config/wazuh.env` và phải nằm ngoài Git. Read tools được gọi tự động; active-response/write tools cần operator confirmation và `confirm=true` ở upstream MCP.

## 🛡️ Wazuh Config Manager

Chỉ các target sau được phép thay đổi:

```text
/var/ossec/etc/rules/local_rules.xml
/var/ossec/etc/decoders/local_decoder.xml
/var/ossec/etc/ossec.conf
```

Mỗi lần ghi phải có `approval_id` và `approved=true`. Hệ thống backup, ghi atomic, validate XML và chạy `wazuh-analysisd -t`. Privilege được giới hạn qua `/usr/local/sbin/agentwazuh-wazuh-config` và sudoers rule riêng; không cấp sudo shell tổng quát.

## 📊 SoL-Pi evidence pipeline

`POST /api/wazuh/investigate` tạo ObservationPack tại `data/solpi_wazuh/`, gồm snapshot alert/status, receipt có hash và compact context cho AI. Khi cần đọc evidence gốc:

```text
GET /api/solpi/observations/{handle}?offset=0&limit=16384
```

API trả dữ liệu theo trang và `next_offset`; cần session đã đăng nhập. Các runtime data, audit logs và config backup không được commit.

## 📡 API nhanh

```text
GET  /api/wazuh/status
GET  /api/wazuh/alerts?limit=50&offset=0
GET  /api/wazuh/correlation?window_sec=3600
POST /api/wazuh/investigate
POST /api/chat
GET  /api/chat/history?session_id=<id>
GET  /api/system/settings
POST /api/system/settings
GET  /api/solpi/observations/{handle}
```

Các endpoint mutation và active response yêu cầu authentication, CSRF/session policy và/hoặc operator approval tùy workflow.

## 🧩 Dependencies

Các dependency chính trong `requirements.txt`:

- FastAPI, Uvicorn, Pydantic
- Requests, HTTPX, urllib3
- LangGraph và MCP
- python-telegram-bot
- cryptography và python-dotenv
- NetworkX

Cài đặt chính xác bằng:

```bash
python -m pip install -r requirements.txt
```

## 🛠️ Troubleshooting

### `HTTP 401 Unauthorized` từ Wazuh API

Kiểm tra host, port, user/password và TLS certificate. Wazuh 4.x cấp Bearer Token qua:

```text
POST /security/user/authenticate?raw=true
```

Client có JWT cache và refresh khi token hết hạn.

### Agent hiển thị `Never connected`

Key từ `/agents/{id}/key` có thể là Base64; cần decode trước khi ghi vào `client.keys`. Đồng thời kiểm tra `<address>` trong `/var/ossec/etc/ossec.conf` và restart `wazuh-agent`.

### `Duplicate agent name`

Dùng key của agent đã đăng ký hoặc xóa agent cũ qua Wazuh API trước khi đăng ký lại; không chạy `agent-auth` lặp lại một cách tùy ý.

### Port đã được sử dụng

```bash
lsof -i :8080
lsof -i :9090
fuser -k -9 8080/tcp
fuser -k -9 9090/tcp
```

### `ModuleNotFoundError`

Chạy lệnh từ thư mục root repository và kích hoạt đúng virtualenv. Import service theo package đầy đủ, ví dụ:

```python
from services.correlation_engine import correlate_alerts
```

## ⚠️ Giới hạn hiện tại

- Cần kiểm thử integration với Wazuh/OpenSearch thật trước khi dùng production.
- LLM provider cần timeout, quota và rate limit phù hợp khi triển khai public.
- `data/` và config backup có thể chứa dữ liệu nhạy cảm; cần quyền filesystem chặt chẽ và encryption nếu cần.
- Không có sẵn HA/clustering trong launcher hiện tại.

## 📚 Tài liệu liên quan

- [Project onboarding](PROJECT_ONBOARDING.md)
- [Project status summary](PROJECT_STATUS_SUMMARY.md)
- [Bug and fixes log](.ai/memory/bugs.md)
- [GitHub Issues](https://github.com/PhongTran0808/AgentWazuh/issues)

## 📜 License

Xem file [LICENSE](LICENSE).

**Maintainer:** PhongTran0808  
**Last updated:** 2026-10-01
