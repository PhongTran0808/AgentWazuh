# Báo Cáo Quét Mã Nguồn AgentWazuh

**Phạm vi:** Toàn bộ repo AgentWazuh (Python + web JS) tại `/run/media/kweismann/Dir_D/Tiểu luận CN/AgentWazuh`
**Ngày quét:** 17/09/2026
**Phương pháp:** Đọc mã nguồn tĩnh, `py_compile`, phân tích route/auth bằng AST, đối chiếu với chính sách trong `.pi/` (zero-mock-data, HITL, no-direct-write).

---

## 1. Lỗi Nghiêm Trọng (Critical)

### 1.1 Authentication bị vô hiệu hóa gần như hoàn toàn
- `core/server.py:192-214` `verify_admin_credentials()`:
  - Trả về `True` cho **bất kỳ mật khẩu nào** nếu username nằm trong `["admin", "wazuh", "wazuh-user", "root"]` hoặc **username rỗng** (dòng 197).
  - Trả về `True` nếu mật khẩu nằm trong danh sách phổ biến `["admin123","admin","wazuh","123456","password"]` (dòng 200) – bất kể username.
  - Trả về `True` nếu file auth không tồn tại **hoặc bất kỳ exception** (dòng 203-214) → fail-open.
  - Hệ quả: login chỉ mang tính hình thức; tài khoản `admin` + mật khẩu bất kỳ đều đăng nhập được.
- `web/login.js:52-53`: mặc định sẵn `username="admin"`, `password="admin123"` → người dùng click đăng nhập không cần gõ gì.

### 1.2 `admin_auth.json` bị tạo lại từ đầu mỗi lần khởi động
- `core/server.py:179-190`: `initialize_admin_auth()` được gọi **ở module level** mỗi khi server chạy → sinh salt + hash mới từ env `AGENTWAZUH_ADMIN_PASSWORD` (mặc định `admin123`) và **ghi đè** mọi mật khẩu đã đổi trước đó.
- Kết hợp 1.1 → toàn bộ hệ thống đăng nhập là giả.

### 1.3 JWT Wazuh rò rỉ qua endpoint không cần đăng nhập
- `services/wazuh_client.py:38-71`: `record_live_api_log()` lưu **toàn bộ `headers`** (gồm cả `Authorization: Bearer <JWT>`) vào `LIVE_API_LOGS` (deque maxlen=100).
- `core/server.py:803-806` `/api/wazuh/live-logs` **không yêu cầu session** → bất kỳ ai truy cập đều lấy được JWT live của Wazuh API.
- Hệ quả: chiếm quyền truy cập Wazuh Manager API (port 55000) với token hợp lệ.

### 1.4 Nhiều endpoint "nhạy cảm" không có xác thực
| Endpoint | Dòng | Vấn đề |
|---|---|---|
| `POST /api/wazuh/webhook` | 765 | Nhận alert bất kỳ, chèn vào `GLOBAL_ALERTS_CACHE`, không kiểm tra nguồn/non-repudiation |
| `GET /api/wazuh/live-logs` | 803 | Rò JWT (xem 1.3) |
| `GET /api/system/audit-logs` | 823 | Lộ nhật ký hoạt động |
| `DELETE /api/system/audit-logs` | 832 | Xóa nhật ký mà không cần auth |
| `POST /api/wazuh/correlation` | 448 | Kích hoạt phân tích tốn chi phí LLM/OpenSearch, kẻ lạ dùng làm `scam`/DoS |
| `GET/POST /api/push/{token}` | 760-763 | Không xác thực ngoài token trong URL (token chỉ là literal) |

### 1.5 Rò rỉ / commit dữ liệu nhạy cảm vào Git
File đang được **tracked** trong git dù `gitignore` đã liệt kê nhiều mục:
- `config/vault_master.key` – khóa master **dạng plaintext**.
- `config/device_vault.enc` – kho dữ liệu mã hóa (không code nào dùng).
- `config/sessions.json` – token phiên đang hoạt động (6 phiên).
- `config/system_settings.json` – chứa `wazuh_pass`, `wazuh_dashboard_pass`, `uptime_kuma_push_token` (file nằm trong `.gitignore` **nhưng vẫn được track** do commit trước khi bổ sung ignore).
- `data/chat_sessions/*.json` – nội dung hội thoại người dùng.
- `config/pending_rules/*.xml` – rule áp dụng.

### 1.6 Vi phạm chính sách ZERO MOCK DATA (tự chế dữ liệu giả)
- `mcp_layer/wazuh_mcp.py:50-55`: khi Wazuh offline, `get_agents()` trả về **agent mô phỏng cứng** (`Ubuntu-Agent`/`10.10.10.2`) → UI/LLM hiển thị agent không có thật, trái với `.pi/policies/strict_grounding.md`.
- `langgraph_engine/graphs/config_form_graph.py:39-79` `dry_run_check_node()`: **bịa kết quả Sandbox** bằng `random.randint(100100,100999)`, `historical_matches=14`, `false_positive_rate="0.0%"` thay vì chạy `dry_run_rule()` thật → và còn `case_manager` tự động dispatch Case (severity HIGH) chưa qua kiểm chứng.
- Dòng 61-72: tự động gửi Case webhook trước khi người dùng phê duyệt → **vi phạm HITL** (`.pi/policies/hitl_safety.md`: không tự động ghi/áp dụng).

### 1.7 `apply_rule` ghi đè `local_rules.xml` gốc
- `core/server.py:1642-1678`: cứ mỗi rule được "apply" là ghi đề cả `config/local_rules.xml` (dòng 1668-1669) bằng XML mới sinh → phá vỡ các rule gốc (100001, 100011, 100021) và không dùng cơ chế `dry_run` thật.
- Không thực sự reload Wazuh manager mà vẫn báo `"reloaded_wazuh": True`.

---

## 2. Lỗi Trung bình (Medium)

### 2.1 Bỏ qua xác thực TLS (SSL/TLS verification off)
- `mcp_layer/wazuh_mcp.py:29,41,63`, `mcp_layer/correlation_mcp.py:121` (`ssl.CERT_NONE`), `services/case_manager.py:88`: tất cả dùng `verify=False` → man-in-the-middle, lộ credential.

### 2.2 Blocking call trong async handler
- `core/server.py:1523-1527`: endpoint `/api/wazuh/investigate` (async) gọi trực tiếp `get_system_status()` + `get_alert_stats_aggregated()` đồng bộ (4-8 giây) → nghẽn event loop, tăng latency toàn bộ server. Đã có comment "PERFORMANCE FIX" (dòng 1488-1495) nhưng rẽ nhánh `if/else` ở 1492-1495 **gán cùng giá trị** (dead code), và vẫn gọi blocking ở 1525-1526.

### 2.3 Đồng bộ môi trường/bí mật lộn xộn
- `core/server.py:26` và `services/incident_assistant.py` đọc `pass.env`/`.env` **hai nơi riêng biệt** (multi-parse).
- `config/system_settings.json` + `sync_pass_env_from_settings()` ghi password vào `pass.env` dạng plaintext lên đĩa.

### 2.4 Nhập/xuất dữ liệu lỏng lẻo
- `/api/wazuh/alerts/import` (`core/server.py:852`) chấp nhận JSON bất kỳ từ client đã đăng nhập → nhiễm bẩn `GLOBAL_ALERTS_CACHE`, ảnh hưởng phân tích sau đó.
- `services/wazuh_client.py:417`: `[0]` trên `affected_items` có thể rỗng → crash bị bọc try/except trả về `offline` sai.

### 2.5 Chạy LLM không kiểm soát chi phí
- `/api/wazuh/correlation` và `/api/wazuh/investigate` không giới hạn tần suất / quota → kẻ đã login (hoặc chưa đăng nhập ở 1.4) có thể burn API keys.

### 2.6 Port không nhất quán giữa README và code
- README.md:27 ghi Port **8080** nhưng `server.py:13` chạy **8000**; `core/server.py:1766` chạy 8080 khi chạy trực tiếp. `run_both_agentwazuh_services.py` khai Port 8080 trong in ra nhưng lại chạy `server.py` (8000). Người dùng theo README truy cập sai port.

### 2.7 Sai readme/tài liệu
- README đưa lệnh `python3 /tmp/start_agentwazuh_and_sodomang.py` (file không tồn tại trong repo; thực tế có `run_both_agentwazuh_services.py`) → hướng dẫn chạy sai.

---

## 3. Lỗi Nhỏ (Low)

### 3.1 Code chết / import thừa
- `core/server.py:44-45`: import `get_agents, search_alerts, get_manager_status, search_correlated_events` nhưng **không dùng** trong module.
- `mcp_layer/wazuh_mcp.py:121`: import `OpenSearchCorrelationTool` không dùng.
- `langgraph_engine/graphs/config_form_graph.py:3`: import `Dict, Any, List, Optional` không dùng (chỉ `logging`, `random`, `StateGraph` được dùng).

### 3.2 Import không dùng trong các service
- `services/correlation_engine.py`: `List`, `hashlib`, `time` thừa; `tools/case_management_tool.py`: `Any`, `Dict`; `server.py`: import `app` không dùng trực tiếp.

### 3.3 Test chưa chạy được trong môi trường hiện tại
- `python3 -m py_compile` toàn bộ: **EXIT 0** (không lỗi cú pháp).
- ĐÃ tạo `.venv` + `requirements-dev.txt` (thêm `pytest`, `pytest-asyncio`, `rich`) và `pytest.ini` (`asyncio_mode = auto`). **Kết quả: 21/21 test PASS** (bao gồm `test_diagnostic_e2e`, `test_ghost_nodes_isolation`, `test_settings`, `test_solpi_wazuh`, `test_correlation_*`).
- Lưu ý test isolation: các test import `GLOBAL_SYSTEM_STATUS_CACHE`/`GLOBAL_ALERTS_CACHE` theo tham chiếu, nên code phải **cập nhật tại chỗ** (`.clear()/.update()`, `[:]`, `del`) thay vì gán lại biến global — đã sửa ở heartbeat/login/update_settings/investigate/webhook/alerts-import.

---

## 4. File Dư Thừa / Dead Code (Có thể xóa hoặc dọn)

| File | Lý do |
|---|---|
| `services/retrieval_engine.py` (339 dòng) | Không được import ở bất kỳ module nào (chỉ tự tham chiếu). |
| `sync_topology.py` | Cứng hóa mock FortiGate response; trỏ `vault_credentials.json` không tồn tại. Không được gọi từ runtime. |
| `config/vault_master.key`, `config/device_vault.enc` | Không code nào dùng, nhưng bị commit (key plaintext) → **phải gỡ khỏi git + xoay khóa**. |
| `config/sessions.json`, `data/chat_sessions/*.json` | Dữ liệu runtime bị track vào git → thêm vào `.gitignore` và `git rm --cached`. |
| `server_9090.py` + `run_both_agentwazuh_services.py` | Hai hệ thống port 9090/8080 chồng lấn nhau, mình core server đã serve dashboard; đọc lại xem có cần tách 9090 không. |
| `package.json` / `node_modules` (pi-mcp-adapter, pi-memory…) | Chỉ phục vụ `pi` CLI ngoài repo; không file Python nào import npm package. Nếu không dùng `pi`, có thể xóa. |
| `install_and_run.sh` vs `start_agentwazuh.sh` | Hai script khởi động gần như trùng nhau (pip install + run server). Gộp/bỏ bớt 1. |

---

## 5. Khuyến Nghị Ưu Tiên

1. **Sửa auth ngay** — bỏ fail-open trong `verify_admin_credentials`, không chấp nhận mật khẩu mặc định, không tạo lại `admin_auth.json` mỗi lần khởi động.
2. **Thêm `Depends(require_authenticated_session)`** vào: `/api/wazuh/live-logs`, `/api/system/audit-logs` (GET/DELETE), `/api/wazuh/webhook`, `/api/wazuh/correlation`, `/api/push/{token}`.
3. **Không ghi `headers` chứa JWT** vào `LIVE_API_LOGS`.
4. **Bỏ dữ liệu mock** (fallback agents, sandbox giả 1.6), thay bằng trạng thái trống thật thà ("EMPTY STATE HONESTY" theo policy).
5. **`apply_rule`:** không ghi đè `local_rules.xml`; chỉ ghi vào `pending_rules/` và tôn trọng HITL thực sự.
6. **Bật SSL verification**, dùng biến môi trường thay vì hardcode `verify=False`.
7. **Gỡ file nhạy cảm khỏi git** (`git rm --cached` + thêm `.gitignore`) và xoay `vault_master.key`.
8. **Thống nhất port** (README / script / code) về một giá trị (8080).

---

## 6. Tình Trạng Khắc Phục (đã sửa ngày 17/09/2026)

| # | Lỗi | Trạng thái | Ghi chú thay đổi |
|---|---|---|---|
| 1.1 | Auth fail-open | ✅ Đã sửa | `verify_admin_credentials()` chỉ chấp nhận user `admin`, so khớp PBKDF2 bằng `compare_digest`, fail-closed khi lỗi/thiếu dữ liệu. |
| 1.2 | Tạo lại `admin_auth.json` mỗi lần boot | ✅ Đã sửa | `initialize_admin_auth()` trả về sớm nếu file đã tồn tại. |
| 1.3 | Rò JWT qua `live-logs` | ✅ Đã sửa | `record_live_api_log()` thay `Authorization` bằng `<JWT_TOKEN>` trước khi lưu; thêm session bắt buộc. |
| 1.4 | Endpoint thiếu auth | ✅ Đã sửa (một phần) | Thêm session cho `live-logs`, `audit-logs` (GET/DELETE), `correlation`; webhook dùng shared-secret `webhook_token`/`WAZUH_WEBHOOK_TOKEN`; `/api/push/{token}` so khớp `uptime_kuma_push_token` (fail-closed). |
| 1.5 | Commit secret vào Git | ✅ Đã sửa (index) | Cập nhật `.gitignore`, `git rm --cached` các file `admin_auth/ai_config/device_vault/known_devices/sessions/system_settings/vault_master.key`, `pending_rules/*.xml`, `data/chat_sessions/*.json`. **Cần xoay khóa `vault_master.key` và đổi mật khẩu.** |
| 1.6 | Mock data | ✅ Đã sửa | `get_agents()` trả `[]` khi offline; `dry_run_check_node()` gọi `dry_run_rule()` thật với `sample_alerts`; bỏ auto-dispatch Case. |
| 1.7 | Ghi đè `local_rules.xml` | ✅ Đã sửa | Chỉ ghi vào `config/pending_rules/`, `reloaded_wazuh=False`, thông báo yêu cầu áp dụng thủ công. |
| 2.1 | Bỏ xác thực TLS | 🟡 Một phần | `mcp_layer/wazuh_mcp.py` đọc `WAZUH_VERIFY_SSL`; `services/case_manager.py` đọc `THEHIVE_VERIFY_SSL`; `correlation_mcp.py` vốn đã đọc `OPENSEARCH_VERIFY_CERTS`. Tất cả default `false` để tương thích cert self-signed của lab — nên bật `true` khi lên production. |
| 2.4 | `affected_items[0]` crash | ✅ Đã sửa | `get_system_status()` kiểm tra list rỗng trước khi lấy `[0]` ở `/manager/info`. |
| 2.2 | Blocking call trong async | ✅ Đã sửa | `login`, `update_settings`, `investigate` offload qua `run_in_executor`; bỏ dead branch; cache thêm `_cached_at`. |
| 2.6 | Port không nhất quán | ✅ Đã sửa | `server.py` + 2 script thống nhất 8080 (theo README + `core/server.py`). |
| 2.7 | README sai path | ✅ Đã sửa | Đổi lệnh thành `python3 run_both_agentwazuh_services.py`. |
| 3.1 | Import thừa | ✅ Đã sửa | Bỏ import không dùng ở `core/server.py` (`JSONResponse`, `get_agents`...), `wazuh_mcp.py` (`OpenSearchCorrelationTool`), `config_form_graph.py` (`Dict, Any, List, Optional`). |
| 3.3 | Test không chạy được | ✅ Đã sửa | Tạo `.venv` + `pytest.ini` + `requirements-dev.txt`; **21/21 PASS**. |
| 4 | File dư thừa | ✅ Một phần | Đã xóa `services/retrieval_engine.py` và `sync_topology.py` (không được import). `server_9090.py` **giữ nguyên** — là tool dự phòng của người dùng, đã xác nhận vẫn hoạt động ở cổng 9090. |

**Còn lại (chưa xử lý):** 2.3 (multi-parse env / ghi password ra `pass.env`), 2.4 phần nhập alert lỏng lẻo (`/api/wazuh/alerts/import`), 2.5 (rate limit LLM).

**Kiểm chứng bằng smoke test (17/09/2026):**
- `server.py` (cổng 8080): `/login` → HTTP 200; `/api/wazuh/live-logs`, `/api/wazuh/correlation`, `/api/system/audit-logs`, `/api/wazuh/webhook` (thiếu token), `/api/push/<sai>` đều → **HTTP 401**; không có Traceback.
- `server_9090.py` (cổng 9090): `/` → HTTP 200 (tool dự phòng vẫn chạy).
- Phát hiện & đã sửa thêm 1 bug khi test: endpoint `/api/push/{token}` dùng tham số tên `status` che module `fastapi.status` → `AttributeError` 500; đổi sang `status_code=401`.
- Không còn process/cổng treo sau test (8080, 9090 đã giải phóng).

---

## 7. Ghi Chú Giao Diện (UI) — Cho đợt nâng cấp UI sau

- **Đăng nhập:** đã bỏ prefill cứng `value="admin"` / `value="admin123"` trong `web/login.html` và bỏ fallback trong `web/login.js`. Nếu UI mới có "ghi nhớ đăng nhập", phải dùng cơ chế an toàn (không hardcode credential).
- **Cookie phiên:** mọi `fetch()` tới endpoint nay yêu cầu session PHẢI có `credentials: "same-origin"`. Đã thêm cho `network_map.js` (`/api/wazuh/live-logs`); các fetch trong `app.js` đã có sẵn. UI mới phải giữ nguyên quy tắc này.
- **Webhook:** `/api/wazuh/webhook` giờ yêu cầu header `X-AgentWazuh-Token` (hoặc `Authorization: Bearer`) khớp `webhook_token` trong settings. Form cấu hình UI cần ô nhập/ẩn token này (không hiển thị plaintext, cho phép "đổi token").
- **Push heartbeat:** `/api/push/{token}` chỉ hoạt động khi token khớp `uptime_kuma_push_token`; UI cần hiển thị trạng thái có/không cấu hình token.
- **Dry-run Rule:** kết quả sandbox giờ là số thật (`historical_matches = 0` khi không có alert mẫu, `status = ERROR` khi lỗi dữ liệu). UI không nên hardcode kỳ vọng "PASS 14 mẫu".
- **Áp dụng Rule:** sau khi "apply", rule chỉ nằm ở `pending_rules/` và `reloaded_wazuh=false`. UI mới cần nút/trạng thái "Chờ áp dụng thủ công lên Wazuh" thay vì báo "thành công trên Manager".
- **Port:** dashboard/API chạy cổng **8080** (không còn 8000).
