# Prompt: Tích hợp Wazuh-MCP-Server vào AI Agent Python (full write access)

## Mục tiêu
Tôi muốn nâng cấp agent này để nó có thể **tự cấu hình Wazuh SIEM** (bao gồm sửa rule, decoder, ossec.conf, quản lý agent, active response...) khi tôi ra lệnh bằng ngôn ngữ tự nhiên, thông qua MCP server: https://github.com/gensecaihq/Wazuh-MCP-Server

- **Mức quyền mong muốn**: FULL ACCESS — bao gồm cả các thao tác sửa rule, decoder, và cấu hình sâu (không chỉ dừng ở active response/chặn IP)

## Việc cần làm

### 1. Setup Wazuh-MCP-Server
- Clone repo `gensecaihq/Wazuh-MCP-Server` về máy Wazuh server (ngay trong folder AgentWazuh này)
- Cấu hình `.env`:
  - `WAZUH_API_HOST` = IP của Wazuh server trên VMware
  - `WAZUH_API_PORT` = 55000
  - `WAZUH_INDEXER_HOST` = IP của Wazuh server, `WAZUH_INDEXER_PORT` = 9200
  - **dùng credentials chuẩn và document lại các bước tạo user đó trong README của project.
  - Set scope: `MCP_API_KEY_SCOPES="wazuh:read wazuh:write"` để bật đầy đủ các tool ghi/thay đổi cấu hình.

### 2. MCP Client trong AI Agent (Python)
- Dùng `mcp` SDK chính thức của Python, transport phù hợp với việc gọi qua network (SSE/HTTP thay vì stdio, vì 2 máy khác nhau).
- Viết một module riêng (ví dụ `wazuh_mcp_client.py`) chịu trách nhiệm:
  - Khởi tạo session, `list_tools()`, `call_tool()`
  - Convert danh sách tool MCP sang format tool-schema chung, rồi từ đó adapt sang từng LLM provider cụ thể (Claude dùng `input_schema`, OpenAI-compatible dùng `parameters`, v.v.) — nên có 1 hàm adapter cho mỗi provider để dễ thêm provider mới sau này.
  - Xử lý lỗi kết nối mạng (timeout, retry) vì 2 máy giao tiếp qua network.

### 3. An toàn khi cấp full write access (bắt buộc, không tùy chọn)
Vì agent sẽ có quyền sửa rule/decoder/cấu hình sâu — đây là các thay đổi có thể làm hỏng khả năng phát hiện tấn công của chính hệ thống nếu AI hiểu sai ý người dùng. Cần:
- **Backup tự động trước mỗi lần ghi**: trước khi gọi bất kỳ tool nào thay đổi rule/decoder/config, tự động backup file/config hiện tại (có timestamp) để có thể rollback.
- **Human-in-the-loop cho thao tác rủi ro cao**: với các tool sửa rule, decoder, hoặc cấu hình cluster — agent phải hiển thị rõ "sẽ thực hiện thay đổi gì" và chờ xác nhận (yes/no) từ tôi trước khi thực thi, không tự động chạy ngầm.
- **Audit log đầy đủ**: mọi lệnh gọi tool write phải được ghi log riêng (ai yêu cầu, prompt gốc, tool nào, tham số gì, kết quả, timestamp) vào file log tách biệt.
- **Validate trước khi gửi**: nếu LLM sinh ra rule/XML không hợp lệ cú pháp, phải validate cú pháp trước khi apply vào Wazuh, không apply mù.

### 4. Kiểm thử
- Viết test kết nối cơ bản: agent gọi tool đọc (list agent, get alert) trước để xác nhận network + auth hoạt động, trước khi test bất kỳ tool ghi nào.
- Cung cấp ít nhất 2-3 kịch bản test cho write action (ví dụ: "tạo rule chặn brute force SSH") chạy trên môi trường Wazuh test/VMware này trước, không áp dụng thẳng vào production.

### 5. Bàn giao
- README rõ cách setup `.env`, cách chạy MCP server, cách agent Python kết nối tới.
- Danh sách các tool nào thuộc nhóm "cần xác nhận thủ công" vs "tự động chạy".
- Ghi chú rõ giới hạn hiện tại (ví dụ provider LLM nào đã test, provider nào chưa).
