# AgentWazuh — SOC AI Incident Assistant

> **Xây dựng hệ thống AI hỗ trợ phân tích, tương quan và ưu tiên cảnh báo an ninh mạng trong SOC**  
> *Đề tài Tiểu luận Chuyên ngành An toàn Thông tin*

---

## 📌 Giới Thiệu Đề Tài

**AgentWazuh** là một hệ thống Trợ lý AI và nền tảng xử lý cảnh báo, được triển khai tích hợp trực tiếp vào môi trường **Wazuh SIEM / SOC**. Dự án hỗ trợ nhà phân tích an toàn thông tin (SOC Analyst) trong quá trình đọc hiểu, tóm tắt bằng chứng, tương quan cảnh báo (Correlation), và đánh giá độ ưu tiên (Priority Scoring) hoàn toàn tự động.

Hệ thống kết hợp sức mạnh tính toán logic thuần (Python) để xử lý dữ liệu và sức mạnh của AI (qua PI Agent / OpenRouter API) để diễn giải ngữ nghĩa, đảm bảo câu trả lời minh bạch, giải thích được và hoàn toàn dựa trên dữ liệu thật.

---

## 🏗️ Phạm Vi Dự Án (Project Scope)

Dự án được thiết kế dưới 2 khía cạnh rõ ràng để đáp ứng yêu cầu chấm điểm học thuật lẫn giá trị thực tiễn:

### 1. [CORE-THESIS] — Trọng Tâm Chấm Điểm
Đây là 3 module logic lõi (thuần Python, không phụ thuộc AI), quyết định tính chuyên môn của đề tài:
- **Deduplication Engine**: Lọc và loại bỏ cảnh báo trùng lặp (giảm nhiễu) trong khung thời gian 60 giây.
- **Correlation Engine**: Nhóm các cảnh báo liên quan lại với nhau dựa trên IP nguồn/đích hoặc Rule ID, tạo thành **Incident Group** thay vì từng cảnh báo riêng lẻ.
- **Priority Scoring System**: Tính điểm ưu tiên (0-100) cho từng nhóm sự cố dựa trên mức độ nghiêm trọng của Rule, ma trận MITRE ATT&CK (Static Lookup) và độ quan trọng của tài sản (Asset Criticality).

### 2. [EXTENSION] — Tính Năng Bổ Trợ (Điểm Cộng Thực Tiễn)
- **AI Master Advisor**: Chatbot AI diễn giải dữ liệu sử dụng mô hình qua OpenRouter (hoặc Local Ollama) thông qua công cụ PI CLI offload. Không cho phép AI tự động chặn IP (1-Click Remediation giữ thủ công).
- **Giao diện SOC Dashboard**: Web UI hiện đại với các biểu đồ, chế độ xem gộp (Incident Group) hoặc đơn lẻ (Single Alert), tích hợp cơ chế bảo mật xác thực phiên.
- **Dynamic Network Map**: Vẽ tự động cấu trúc mạng từ dữ liệu thiết bị (Node/Link) và IP thu thập được.

---

## 🏛️ Kiến Trúc Hệ Thống (Hybrid Architecture)

```text
 ┌─────────────────────────────────────────────────────────────┐
 │               User / SOC Analyst Web Dashboard              │
 └──────────────────────────────┬──────────────────────────────┘
                                │ (HTTP REST API)
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                FastAPI Web Server (Port 8080)               │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │        [CORE-THESIS] Python Correlation Engine (Logic)      │
 │  (Deduplicate -> Correlate (Incident) -> Priority Score)    │
 └──────────────┬──────────────────────────────┬───────────────┘
                │                              │
                ▼                              ▼
 ┌──────────────────────────────┐ ┌────────────────────────────┐
 │  Wazuh REST API Client       │ │  PI Agent / OpenRouter API │
 │  (Data Ingestion / Webhook)  │ │  (AI Semantics & Summary)  │
 └──────────────┬───────────────┘ └──────────────┬─────────────┘
                │                              │
                ▼                              ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                 Wazuh Manager (SIEM Server)                 │
 └─────────────────────────────────────────────────────────────┘
```

---

## ✨ Tính Năng Nổi Bật

- 🔄 **Tương Quan Cảnh Báo (Correlation)**: Tự động gom nhóm hàng ngàn cảnh báo thành các Incident Group gọn gàng.
- 🎯 **Chấm Điểm Rủi Ro (Priority Scoring)**: Mỗi nhóm sự cố đều được chấm điểm ưu tiên dựa trên tài sản (Asset Criticality) và Tactic MITRE.
- 👁️ **Minh Bạch Dữ Liệu AI**: Hệ thống ghi nhận mọi dữ liệu chuyển ra AI bên ngoài (OpenRouter) vào file log `logs/openrouter_audit.log` (có đính kèm trạng thái lọc IP nội bộ).
- 🌐 **Con Chat Tổng SOC Master (Global Advisor)**: Hỗ trợ 2 chế độ (Hỏi đáp toàn bộ bối cảnh hệ thống SOC hoặc Điều tra sâu). AI chỉ được phép đọc dữ liệu (Zero Hallucination).
- ⚡ **Quản Trị Thiết Bị Tự Động**: Nạp và ghi đè known devices và vẽ topology động.

---

## 📝 Giấy Phép & Tác Giả

- **Tác giả**: PhongTran0808 (`phongtran080809@gmail.com`)
- **Kho lưu trữ**: [https://github.com/PhongTran0808/AgentWazuh](https://github.com/PhongTran0808/AgentWazuh)
- **Giấy phép**: MIT License
