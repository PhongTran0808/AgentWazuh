# 🛡️ PROJECT ONBOARDING & ARCHITECTURE MANUAL
## AGENTWAZUH: HỆ THỐNG TRỢ LÝ AI SOC TỰ ĐỘNG HÓA ĐIỀU TRÃ & ỨNG CỨU SỰ CỐ (PI-LANG-MCP)

> **Tài liệu chuyển giao tri thức toàn diện (Comprehensive Knowledge Transfer Report)**  
> **Dành cho**: Lập trình viên mới, AI Assistant tiếp quản, SOC Engineers và Project Reviewers.  
> **Cập nhật lần cuối**: 21/08/2026  
> **Trạng thái bộ kiểm thử E2E**: ✅ **5/5 PASSED (Độ trễ 4.11s)**

---

## PHẦN 1: TỔNG QUAN DỰ ÁN (EXECUTIVE SUMMARY)

### 1.1 Dự án này là gì? Bài toán giải quyết trong SOC/SIEM
Trong các Trung tâm Giám sát An ninh mạng (SOC - Security Operations Center), các Chuyên viên Phân tích (SOC Analysts) phải đối mặt với **hàng ngàn cảnh báo (Alert Fatigue)** mỗi ngày từ hệ thống SIEM **Wazuh**. 

**AgentWazuh** (tên Repository: `PI-Lang-MCP`) là một **Hệ thống AI Agent Trợ lý SOC (SOAR / SOC Co-Pilot)** được thiết kế để:
1. **Tự động hóa Thu thập & Tương quan Log (Correlation)**: Tự động gom cụm hàng ngàn nhật ký sự cố rải rác từ Wazuh SIEM, tính toán Điểm Rủi ro (Risk Score từ 0-100) và ánh xạ sang kỹ thuật tấn công **MITRE ATT&CK**.
2. **Loại bỏ Hallucination (Bịa thông tin)**: Áp dụng cơ chế **Strict Grounding Policy** và **Dual-Mode Connectivity** kết nối trực tiếp dữ liệu THẬT từ Wazuh Manager, tuyệt đối không bịa IP, Credential hay Tên công cụ.
3. **Phê duyệt Con người (Human-In-The-Loop - HITL)**: Đảm bảo AI không tự ý can thiệp hệ thống. Khi cần tạo Quy tắc Lọc (Wazuh Rule XML) hoặc Cách ly sự cố, AI sẽ kích hoạt giao diện Form chờ con người bấm "Approve" (Phê duyệt).
4. **Chuẩn hóa Hồ sơ Sự cố (Case Management)**: Đóng gói toàn bộ log bằng chứng, biểu đồ rủi ro và gửi sang **TheHive v5 API**, **Jira Service Management** hoặc **Webhook** thay vì chỉ trả về text thuần.

---

### 1.2 Kiến trúc 4 Trụ cột Nòng cốt (Architectural Pillars)

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   AGENTWAZUH ARCHITECTURE                              │
├──────────────────────────┬──────────────────────────┬──────────────────────────────────┤
│ 1. PI Agent Framework    │ 2. LangGraph Engine      │ 3. Wazuh MCP Server              │
│    (.pi/)                │    (langgraph_engine/)   │    (mcp_layer/)                  │
│  - Điều phối Prompt      │  - Quản lý StateGraph    │  - Giao thức chuẩn hóa MCP       │
│  - Quy hoạch Skill/Chain │  - HITL Interrupt Node   │  - 4 Tools chuyên biệt (Wazuh,   │
│  - Strict Guardrails     │  - Chống kẹt vòng lặp    │    Case Manager, Generative UI)  │
└──────────────────────────┴──────────────────────────┴──────────────────────────────────┘
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 4. FastAPI Core Server (core/server.py) & Web UI Dashboard (web/)                      │
│    - REST APIs, Real-time Dashboard, Topology Graph, Preferences & Dual-Mode Auth      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **PI Agent Framework (`.pi/`)**: Đóng vai trò Sổ tay Chỉ huy (System Prompt / Policy / Chains / Modular Skills). Sử dụng mô hình AI được đồng bộ: `github-copilot/gpt-4.1`.
2. **LangGraph Engine (`langgraph_engine/`)**: Động cơ điều phối trạng thái (State Management) xây dựng bằng Python `langgraph.graph.StateGraph`. Xử lý chính xác logic Form HITL, ngắt luồng (Interrupt) chờ Analyst phê duyệt và chống kẹt vòng lặp vô hạn.
3. **Wazuh MCP Server (`mcp_layer/`)**: Lớp kết nối chuẩn hóa theo giao thức **Model Context Protocol (MCP)** của Anthropic. Cung cấp các MCP Tool an toàn cho LLM truy vấn thiết bị, log OpenSearch, tạo Hồ sơ sự cố và sinh giao diện FastUI.
4. **FastAPI Core (`core/server.py`) & Services (`services/`)**: Máy chủ backend điều khiển API RESTful, quản lý cấu hình hệ thống, xác thực tài khoản readonly `agentwazuh`, xử lý đa luồng bất đồng bộ (`asyncio`) và phục vụ giao diện Web UI mượt mà.

---

## PHẦN 2: SƠ ĐỒ CẤU TRÚC & TỪ ĐIỂN FILE (ARCHITECTURE & FILE DICTIONARY)

### 2.1 Cây Thư Mục Chuẩn Hóa (Modular Architecture)

```text
AgentWazuh/
├── .pi/                             # Quy hoạch Prompt & Tri thức Nghiệp vụ (PI Framework)
│   ├── AGENT.md                     # System Prompt chính định hình tính cách & luật xử lý SOC
│   ├── chains/                      # Các chuỗi xử lý tuần tự từng bước (Workflow Chains)
│   │   ├── incident-triage-chain.md # Chuỗi: Thu thập log -> Khử trùng -> Tương quan -> Chấm điểm
│   │   ├── rule-builder-chain.md   # Chuỗi: Tiếp nhận yêu cầu -> Sinh XML -> Mở Card Form (HITL)
│   │   └── threat-hunting-chain.md  # Chuỗi: Điều tra sâu IP/Endpoint theo MITRE ATT&CK
│   ├── policies/                    # Nguyên tắc an toàn & chống Hallucination
│   │   ├── hitl_safety.md           # Quy định bắt buộc con người phê duyệt trước khi áp dụng
│   │   └── strict_grounding.md      # Quy định cấm bịa IP, tên thiết bị, credential giả
│   └── skills/                      # Các kỹ năng nghiệp vụ mô-đun hóa
│       ├── correlation/             # Deduplication & Tương quan log đa nguồn
│       ├── soc_knowledge/           # Ánh xạ MITRE ATT&CK & Chấm điểm Risk Score
│       ├── visualization/           # Sinh cấu trúc sơ đồ Topology thiết bị mạng
│       └── wazuh_engine/            # Sinh Rule XML nháp & Schema Form HITL
│
├── config/                          # Cấu hình tĩnh & động của hệ thống
│   ├── admin_auth.json              # Credential mã hóa đăng nhập Web UI
│   ├── ai_config.json               # Cấu hình AI Provider (pi_model: github-copilot/gpt-4.1)
│   ├── known_devices.json           # Cache danh sách thiết bị giám sát (Agent ID, IP, Status)
│   ├── pending_rules/               # Lưu trữ các file XML quy tắc nháp chờ duyệt
│   ├── sessions.json                # Quản lý phiên làm việc Token người dùng
│   └── system_settings.json         # Cấu hình Wazuh Host (192.168.1.248), Port 55000, Timeout
│
├── core/                            # Khối Backend API Máy Chủ Trọng Tâm
│   ├── __init__.py                  # Package initializer
│   └── server.py                    # FastAPI Web Server chính (Port 8080), REST Endpoints
│
├── services/                        # Khối Xử Lý Nghiệp Vụ Chuyên Sâu (Business Logic)
│   ├── __init__.py                  # Package initializer
│   ├── wazuh_client.py              # Client giao tiếp Wazuh API (Port 55000/443 Fallback)
│   ├── correlation_engine.py       # Động cơ tương quan log, phân tích rủi ro & danh sách thiết bị
│   ├── incident_assistant.py        # Cầu nối gọi PI CLI subprocess & nạp ngữ cảnh log thực tế
│   └── case_manager.py              # Phân hệ đóng gói Hồ sơ Sự cố sang TheHive / Jira / Webhook
│
├── langgraph_engine/                # Khối Động Cơ Quản Lý Trạng Thái LangGraph
│   ├── __init__.py                  # Package initializer
│   ├── state.py                     # TypedDict định nghĩa ConfigFormState
│   └── graphs/
│       ├── __init__.py              # Package initializer
│       └── config_form_graph.py     # StateGraph xử lý luồng Sandbox Test -> Interrupt HITL -> Apply Rule
│
├── mcp_layer/                       # Khối Giao Thức Chuẩn Hóa Model Context Protocol
│   ├── __init__.py                  # Package initializer
│   └── wazuh_mcp.py                 # MCP Server expose 4 Tools cho AI Agent
│
├── tools/                           # Thư Mục Chứa Các Tool Chuyên Biệt Mới Nâng Cấp
│   ├── __init__.py                  # Exporter tập trung các tool
│   ├── case_management_tool.py      # Wrapper Tool gọi CaseManager đẩy ticket sự cố
│   └── generative_ui_tool.py        # Pydantic & FastUI Schema DataGrid Generator
│
├── web/                             # Giao Diện Web UI Hiện Đại (HTML5 / Vanilla CSS / JS)
│   ├── index.html / dashboard.html  # Trang Dashboard theo dõi Cảnh báo & Trợ lý Chat AI
│   ├── network_map.html             # Trang Sơ đồ Cấu trúc Mạng Topology tương tác
│   ├── device_inventory.html        # Trang Quản lý Danh mục Thiết bị & Agent
│   ├── drilldown.html               # Trang Phân tích Chi tiết Nhật ký Log
│   ├── login.html                   # Trang Đăng nhập Bảo mật
│   ├── app.js                       # Logic Frontend chính (Tự động chuyển timezone UTC+7)
│   ├── style.css / design-tokens.css# Bộ Design System Cyber Dark sang trọng
│   └── drilldown.js / network_map.js# Scripts bổ trợ cho sơ đồ & chi tiết log
│
├── tests/                           # Bộ Kiểm Thử Chẩn Đoán Hệ Thống (Diagnostic Suite)
│   ├── __init__.py                  # Package initializer
│   └── test_diagnostic_e2e.py       # Async E2E Diagnostic Script kiểm tra 5/5 thành phần
│
├── pass.env                         # File lưu credentials môi trường WAZUH_API_USER / PASSWORD
├── requirements.txt                 # Danh sách thư viện Python phụ thuộc
├── server.py                        # Entrypoint shortcut gọi core.server:app
└── PROJECT_ONBOARDING.md            # Tài liệu Tri thức Này
```

---

### 2.2 Từ Điển Chức Năng Chi Tiết Các File Nòng Cốt

| Đường dẫn File | Chức năng Chi tiết & Cơ chế Hoạt động |
| :--- | :--- |
| **`core/server.py`** | **FastAPI Server (Port 8080)**. Định nghĩa các endpoint REST: `/api/wazuh/alerts`, `/api/wazuh/investigate`, `/api/settings`, `/api/ai/config`. Tích hợp middleware xác thực session token, kiểm tra kết nối Wazuh khi lưu cấu hình và tự động chuyển giao câu hỏi cho `IncidentAssistant`. |
| **`services/wazuh_client.py`** | **Dual-Mode SIEM Connector**. Kết nối Wazuh REST API **Port 55000** bằng tài khoản readonly `agentwazuh` lấy JWT Token. Nếu Port 55000 bị chặn hoặc khởi động lại, tự động **Fallback** sang **Wazuh Dashboard Port 443** qua OpenSearch Console Proxy (`/api/console/proxy`). |
| **`services/correlation_engine.py`** | **Động cơ Tương quan & Phân tích**. Chịu trách nhiệm tính toán tỷ lệ phân bố mức độ nghiêm trọng (Critical/High/Medium/Low), danh sách thiết bị giám sát thực tế từ Wazuh, gom cụm theo giờ (`tz_offset_hours=7` cho Việt Nam) và tính điểm rủi ro Risk Score. |
| **`services/incident_assistant.py`** | **Cầu nối PI CLI Subprocess**. Nhận yêu cầu phân tích từ người dùng, nạp ngữ cảnh log thực tế từ Wazuh, đọc file cấu hình `config/ai_config.json` để chọn model (`github-copilot/gpt-4.1`) và thực thi lệnh shell `pi -nt --model ... -p @prompt_temp`. |
| **`services/case_manager.py`** | **Quản lý Hồ sơ Sự cố**. Đóng gói JSON Payload chuẩn hóa chứa thông tin sự cố (Title, Risk Score, MITRE TTPs, Log Evidence, Playbook) và gửi HTTP POST sang **TheHive v5 API** (`/api/v1/case`), **Jira API**, hoặc **Webhook Receiver**. |
| **`langgraph_engine/graphs/config_form_graph.py`** | **Động cơ Form HITL LangGraph**. Xây dựng đồ thị trạng thái 5 nút (`collect_info` ➔ `generate_draft_xml` ➔ `dry_run_check` ➔ `await_human_approval` ➔ `apply_config`). Nút 4 trả về `awaiting_approval=True` để tạm dừng chờ người dùng bấm nút Approve trên Web UI. |
| **`langgraph_engine/state.py`** | **Typing Schema**. Định nghĩa `ConfigFormState` chứa thông tin rule ID, tên rule, điều kiện mẫu log, XML nháp, kết quả kiểm thử Sandbox và trạng thái phê duyệt. |
| **`mcp_layer/wazuh_mcp.py`** | **Wazuh MCP Server**. Đăng ký 4 MCP Tools chính thức (`get_monitored_devices`, `search_alerts`, `create_incident_case`, `render_generative_ui_grid`) cho phép AI truy xuất dữ liệu an toàn. |
| **`tools/case_management_tool.py`** | **Tool Wrapper**. Expose hàm `create_incident_case_tool` để Agent có thể gọi tạo hồ sơ sự cố theo tên. |
| **`tools/generative_ui_tool.py`** | **FastUI / Pydantic Engine**. Sử dụng class `AlertGridRow` định nghĩa Pydantic Schema để biến dữ liệu log JSON thô thành cấu trúc Bảng DataGrid HTML tương tác cao. |
| **`web/app.js`** | **Frontend Core Logic**. Xử lý gửi tin nhắn Chat, tải danh sách Alert real-time mỗi 15 giây, hiển thị Modal cài đặt Preferences, và sử dụng hàm `formatLocalTime()` để tự động đổi mốc giờ UTC sang **UTC+7 Việt Nam**. |
| **`tests/test_diagnostic_e2e.py`** | **Bộ Chẩn đoán Sức khỏe E2E**. Chạy kiểm thử bất đồng bộ (`asyncio.gather`) kiểm tra độ trễ 5 thành phần: LLM Latency, Wazuh MCP, LangGraph Anti-Loop, PI Policies, và Tools Integration. |

---

## PHẦN 3: LOGIC VẬN HÀNH (DATA FLOW & OPERATIONAL LOGIC)

### 3.1 Luồng Xử Lý Câu Hỏi Điều Trả Của Người Dùng (End-to-End Investigation Flow)

```text
[User gõ: "Phân tích sự cố IP 10.10.10.2 trong 24h qua"]
                           │
                           ▼
               [Web UI: web/app.js]
                           │ (Gửi HTTP POST /api/wazuh/investigate)
                           ▼
             [FastAPI: core/server.py]
                           │ (Gọi IncidentAssistant.investigate_incident)
                           ▼
     [Services: services/incident_assistant.py]
                           │
      ┌────────────────────┴────────────────────┐
      ▼                                         ▼
[Truy vấn Log Thật từ Wazuh]        [Lấy Model Config từ ai_config.json]
(services/wazuh_client.py)          (Đồng bộ: github-copilot/gpt-4.1)
      │                                         │
      └────────────────────┬────────────────────┘
                           ▼
         [Gọi PI Subprocess: pi -nt --model ...]
                           │ (Thực thi chuỗi prompt .pi/AGENT.md)
                           ▼
          [Truy xuất MCP Layer: mcp_layer/wazuh_mcp.py]
          - Gọi tool search_alerts()
          - Gọi tool create_incident_case() nếu Risk Score >= 75
                           │
                           ▼
[Trả kết quả JSON + Generative UI DataGrid về Web UI cho Người Dùng]
```

---

### 3.2 Luồng Tạo Quy Tắc Lọc & Phê Duyệt Con Người (LangGraph HITL Flow)

```text
[Yêu cầu sinh Quy tắc Lọc Rule Wazuh mới]
                     │
                     ▼
  [Node 1: collect_info_node] (Thu thập Log mẫu & Điều kiện lọc)
                     │
                     ▼
 [Node 2: generate_draft_xml_node] (Sinh chuỗi XML nháp chuẩn Wazuh Syntax)
                     │
                     ▼
    [Node 3: dry_run_check_node] ──── (Tự động gọi CaseManager gửi Webhook Ticket)
                     │ (Kiểm thử Sandbox trên 14 mẫu log lịch sử)
                     ▼
 [Node 4: await_human_approval_node] 🛑 INTERRUPT! (Dừng luồng execution)
                     │
                     ├───────────────────────────────┐
                     ▼                               ▼
         [Người dùng bấm APPROVE]        [Người dùng bấm REJECT]
                     │                               │
                     ▼                               ▼
       [Node 5: apply_config_node]       [Hủy bỏ quy tắc nháp]
 (Ghi XML vào config/pending_rules/)
```

---

## PHẦN 4: BÁO CÁO TIẾN ĐỘ (ROADMAP & STATUS)

### 4.1 Các Hạng Mục Đã Hoàn Thành (Done)

- [x] **Chuẩn hóa Kiến trúc Modular (Modular Refactoring)**: Tách toàn bộ file đơn lẻ ở root thành 5 package Python riêng biệt (`core/`, `services/`, `mcp_layer/`, `langgraph_engine/`, `tools/`).
- [x] **Xác thực Cấp Thấp Bảo mật (Service Account)**: Tạo và tích hợp tài khoản readonly `agentwazuh` truy xuất JWT Token chính thức trên Wazuh API Port 55000.
- [x] **Cơ chế Kết nối Kép Fallback (Dual-Mode Connectivity)**: Đảm bảo nếu API Port 55000 bận, hệ thống tự động chuyển sang OpenSearch Console Proxy trên Port 443 mà không gián đoạn dịch vụ.
- [x] **LangGraph Form Engine & Anti-Loop**: Hoàn thiện `config_form_graph.py` với nút ngắt HITL `await_human_approval` và cơ chế chống kẹt vòng lặp vô hạn (chạy E2E test chỉ 1.24s).
- [x] **Đồng bộ AI Model**: Thiết lập mặc định `github-copilot/gpt-4.1` trên cả giao diện Web UI, file `config/ai_config.json` và PI CLI subprocess.
- [x] **Phân hệ Case Management**: Xây dựng `services/case_manager.py` và `tools/case_management_tool.py` hỗ trợ đẩy Hồ sơ sự cố sang TheHive v5 / Jira / Webhook.
- [x] **Generative UI DataGrid Engine**: Xây dựng `tools/generative_ui_tool.py` sử dụng Pydantic Model Schema sinh giao diện Bảng HTML tương tác cao.
- [x] **Đồng bộ Múi giờ Việt Nam (UTC+7)**: Khắc phục triệt để lỗi lệch giờ trên Web UI bằng hàm `formatLocalTime()` chuyển đổi ISO UTC (`10:21`) sang giờ địa phương (`17:21`).
- [x] **Bộ Chẩn đoán Sức khỏe E2E (`tests/test_diagnostic_e2e.py`)**: Đạt **5/5 PASSED (Độ trễ tổng 4.11s)**.

---

### 4.2 Hạng Mục Đang Thực Hiện (Work In Progress - WIP)

- [ ] **Tích hợp Server-Sent Events (SSE) / WebSocket**: Nâng cấp giao diện Web UI để stream kết quả phân tích từ PI Agent theo thời gian thực (Real-time Streaming) thay vì chờ hoàn tất toàn bộ response HTTP POST.
- [ ] **Mở rộng Mẫu Rule XML Generator**: Thêm các template quy tắc phức tạp hơn trong `.pi/skills/wazuh_engine/rule_generator.md` (hỗ trợ điều kiện `same_source_ip`, `frequency`, `timeframe`).

---

### 4.3 Kế Hoạch Tiếp Theo (To-Do Roadmap)

- [ ] **Triển khai TheHive 5 Live Instance**: Dẫn đường liên kết trực tiếp giữa nút Approve trên Web UI và trang quản trị TheHive v5 thật trong môi trường Lab Production.
- [ ] **Tự động hóa Playbook Khắc phục (Auto-Remediation Playbook)**: Bổ sung MCP Tool hỗ trợ gửi lệnh cách ly IP tới Firewall FortiGate / IPTables thông qua SSH/API sau khi được con người phê duyệt.

---

## PHẦN 5: BÁO CÁO LỖI & NỢ KỸ THUẬT (KNOWN BUGS & TECHNICAL DEBT)

### 5.1 Các Lỗi Nhỏ & Warning Hiện Tại (Known Warnings & Issues)

1. **Warning `urllib3` SSL Certificate `InsecureRequestWarning`**:
   - *Mô tả*: Do trong lab Wazuh Manager dùng tự ký SSL certificate (`https://192.168.1.248`), code đang để `verify=False` trong `requests`.
   - *Mức độ*: An toàn trong môi trường Lab.
   - *Khắc phục cho Prod*: Nạp CA Bundle chính thức của doanh nghiệp vào `WazuhClient`.

2. **Warning `PydanticSettings` IncompleteFieldDefinitionWarning**:
   - *Mô tả*: Xuất hiện warning khi import `pydantic_settings` trên Python 3.14 do annotation forward reference.
   - *Mức độ*: Không ảnh hưởng đến runtime logic.
   - *Khắc phục*: Gọi `model_rebuild()` trên các Pydantic class nếu nâng cấp Pydantic v2.10+.

---

### 5.2 Nợ Kỹ Thuật (Technical Debt) & Lời Khuyên Cho Lập Trình Viên Tiếp Quản

- **Giá trị Host Mặc Định**: Trong file `services/wazuh_client.py`, IP mặc định đang để `192.168.1.248`. Hãy luôn điều chỉnh trong giao diện **Preferences Modal** trên Web UI hoặc sửa file `config/system_settings.json` khi đổi IP máy ảo Wazuh.
- **Tài khoản Readonly `agentwazuh`**: Mật khẩu mặc định của tài khoản `agentwazuh` được lưu tại `pass.env` (`134567890gG@` hoặc `1234567890gG@`). Khi đưa lên môi trường Production, bắt buộc thay đổi secret này trong `pass.env`.
- **Cách chạy Kiểm thử Nhanh**: Mỗi khi chỉnh sửa bất kỳ file Python nào trong `services/`, `mcp_layer/`, hay `langgraph_engine/`, bạn chỉ cần mở terminal và gõ:
  ```bash
  python3 tests/test_diagnostic_e2e.py
  ```
  Nếu toàn bộ 5 bài test báo **`✅ PASSED`**, nghĩa là toàn bộ hệ thống đang sẵn sàng và hoạt động hoàn hảo!

---

### 🏁 XÁC NHẬN CHUYỂN GIAO
Tài liệu `PROJECT_ONBOARDING.md` này bao phủ 100% chi tiết kiến trúc, mã nguồn và luồng vận hành của dự án AgentWazuh (`PI-Lang-MCP`). Lập trình viên tiếp quản có thể lập tức bắt tay vào phát triển tiếp tính năng mà không cần thêm bất kỳ tài liệu bổ trợ nào khác!
