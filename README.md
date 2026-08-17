# AgentWazuh — Local LLM-based Security Incident Investigation Assistant

> **Xây dựng Trợ lý AI Cục bộ Hỗ trợ Điều tra Sự cố Trong Hệ Thống SOC Wazuh**  
> *Đề tài Tiểu luận Chuyên ngành An toàn Thông tin*

---

## 📌 Giới Thiệu Đề Tài

**AgentWazuh** là một trợ lý AI được triển khai cục bộ (Local LLM), tích hợp trực tiếp vào môi trường **Wazuh SIEM / SOC** nhằm hỗ trợ nhà phân tích an toàn thông tin (SOC Analyst) trong quá trình đọc hiểu, tóm tắt bằng chứng, và điều tra các cảnh báo an ninh.

Hệ thống cho phép người dùng đặt câu hỏi bằng **ngôn ngữ tự nhiên**, tự động đối chiếu dữ liệu log thực tế từ **Wazuh Manager REST API** với ma trận **MITRE ATT&CK**, từ đó đưa ra câu trả lời giải thích được, minh bạch và có căn cứ.

---

## 🏛️ Kiến Trúc 2 Lớp (2-Layer Hybrid Architecture)

```text
 ┌─────────────────────────────────────────────────────────────┐
 │               User / SOC Analyst Query                      │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                FastAPI Web Server (Port 8080)               │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                 Wazuh REST API Client                       │
 │        (VMWare https://192.168.1.240/ + Fallback Engine)      │
 └──────────────┬──────────────────────────────┬───────────────┘
                │                              │
                ▼                              ▼
 ┌──────────────────────────────┐ ┌────────────────────────────┐
 │  Layer 1: Static Lookup     │ │  Layer 2: Local RAG LLM    │
 │  (config/mitre_mapping.json) │ │  (Qwen2.5-3B Q4_K_M Ollama)│
 │  100% Ground-Truth Mapping   │ │  RAM Budget ~2.5GB Max     │
 └──────────────┬───────────────┘ └──────────────┬─────────────┘
                │                              │
                └──────────────┬───────────────┘
                               │
                               ▼
 ┌─────────────────────────────────────────────────────────────┐
 │       Interactive SOC Web UI (Marked.js + Mermaid.js)       │
 └─────────────────────────────────────────────────────────────┘
```

1. **Layer 1 — Static Ground-Truth Lookup (`config/mitre_mapping.json`)**: Bảng tra cứu tĩnh gán trực tiếp Rule ID ↔ MITRE Technique ID cho các trường hợp đã biết, đạt độ chính xác tuyệt đối 100%.
2. **Layer 2 — Local LLM RAG Reasoning (`Qwen2.5-3B-Instruct Q4_K_M`)**: Truy xuất ngữ nghĩa và suy luận ngôn ngữ tự nhiên qua Ollama API (`http://localhost:11434`), khống chế mức RAM tiêu thụ **~2.5GB Max** nhằm ngăn ngừa Out-Of-Memory (OOM).

---

## ✨ Tính Năng Nổi Bật & Tích Hợp GitHub

- 🌐 **Con Chat Tổng SOC Master (Global Advisor)**: Hỗ trợ 2 chế độ (Hỏi đáp toàn bộ bối cảnh hệ thống SOC hoặc Điều tra sâu từng cảnh báo đơn lẻ).
- 🖱️ **Cơ Chế Nhấp Chuột Tương Tác (Interactive Chips)**: Các thẻ nhấp chuột tương tác (`<button class="interactive-chip">`) mở trực tiếp Modal JSON Log Viewer mà không cần nhập lại prompt.
- 📊 **Luồng Suy Luận 4 Bước (Tích hợp từ SecurityClaw)**: Hiển thị Stepper tiến trình (`Step 1 Fetch` ➔ `Step 2 Lookup` ➔ `Step 3 Classify` ➔ `Step 4 Synthesize`) và phân loại rủi ro (`TRUE_THREAT` 🔴 | `SUSPICIOUS` 🟡 | `FALSE_POSITIVE` 🟢).
- 📤 **Đóng Gói Xuất Wazuh OpenSearch Payload (Tích hợp từ Wazuh_claude_analyst)**: Đóng gói JSON chuẩn hóa để đẩy ngược vào OpenSearch Indexer của Wazuh Dashboard.
- ⚡ **Lệnh Tường Lửa 1-Click Copy (Tích hợp từ ThreatSentinel)**: Hiển thị lệnh chặn IP `sudo iptables` kèm nút 1-Click Copy vào Clipboard.
- 📐 **Vẽ Sơ Đồ Attack Chain (Mermaid.js)**: Tự động render sơ đồ luồng xử lý tấn công trực quan.

---

## 👥 Bảng Phân Công 5 Vai Trò Chuyên Biệt

| Vai Trò | Trách Nhiệm | Đầu Ra Sản Phẩm |
| :--- | :--- | :--- |
| **`@claude` (Architect)** | Thiết kế kiến trúc 2 Lớp, API Contract spec | Sơ đồ kiến trúc, API spec |
| **`@rule-designer` (Rule Engineer)** | Thiết kế Wazuh Custom Rules + Tra cứu MITRE | `config/local_rules.xml`, `config/mitre_mapping.json` |
| **`@ui-designer` (UI/UX Engineer)** | Thiết kế Wireframe 3 khung & Design Tokens | `web/design-tokens.css`, `web/style.css` |
| **`@codex` (Implementation)** | Lập trình Python backend & Frontend JS | `wazuh_client.py`, `incident_assistant.py`, `server.py`, `web/app.js` |
| **`@reviewer` (Security Auditor)** | Kiểm định an toàn SSL, OWASP, Anti-Hallucination | Báo cáo kiểm định 2 vòng *(Không sửa code)* |

---

## 🚀 Hướng Dẫn Cài Đặt & Chạy Dự Án

### 1. Yêu cầu hệ thống
- Python 3.10+
- Ollama (`ollama pull qwen2.5:3b`)
- Wazuh SIEM 4.x (VMWare hoặc Server Standalone)

### 2. Tải về và Cài đặt
```bash
# Clone dự án từ GitHub
git clone https://github.com/PhongTran0808/AgentWazuh.git
cd AgentWazuh

# Cài đặt các thư viện phụ thuộc
pip install -r requirements.txt
```

### 3. Khởi chạy Server
```bash
python server.py
```

Mở trình duyệt truy cập: **`http://127.0.0.1:8080`**

---

## ⚠️ Giới Hạn Đã Biết (Known Limitations)

- **Self-Signed SSL Certificate**: Tham số `verify=False` trong `wazuh_client.py` là **giới hạn đã biết của môi trường thử nghiệm Lab** khi kết nối đến IP VMWare (`https://192.168.1.9/`). Đây không phải là thiếu sót mã nguồn.
- **Anti-Hallucination Guard**: Khi dữ liệu nhật ký Wazuh không đủ bằng chứng, AI bắt buộc phản hồi `"Không đủ dữ liệu để kết luận"` nhằm ngăn ngừa việc tự bịa ra thông tin bảo mật sai lệch.

---

## 📝 Giấy Phép & Tác Giả

- **Tác giả**: PhongTran0808 (`phongtran080809@gmail.com`)
- **Kho lưu trữ**: [https://github.com/PhongTran0808/AgentWazuh](https://github.com/PhongTran0808/AgentWazuh)
- **Giấy phép**: MIT License
