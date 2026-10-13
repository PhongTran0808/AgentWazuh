# Hướng Dẫn Tích Hợp Laya Intent Classifier (Active Routing) vào AgentWazuh

## 1. Giới thiệu & Mục tiêu

Tài liệu này mô tả kiến trúc và cách vận hành của bộ phân loại ý định hội thoại **Laya Intent Classifier** được tích hợp trực tiếp vào AgentWazuh.

Mô hình fine-tune (`laya_finetuned_typed_decisions`) dựa trên kiến trúc ModernBERT-large, chạy tăng tốc GPU trên **NVIDIA GeForce RTX 3050 Laptop GPU (CUDA 12.6)** với độ trễ suy luận chỉ **~50ms**, phân loại câu hỏi của người dùng vào 1 trong **9 Intent vận hành chuẩn** và định tuyến trực tiếp vào workflow xử lý tương ứng.

---

## 2. Thông số Môi trường & Checkpoint

- **Thư mục mô hình**: `/home/xinloihuy/Documents/AgentWazuh_dataset/laya_finetuned_typed_decisions`
- **Môi trường Python**: `laya_venv` (Python 3.12, PyTorch 2.14.1+cu126, Laya 0.4.6)
- **VRAM chiếm dụng**: ~1.6 GB (trên 4GB/6GB VRAM của RTX 3050 Laptop GPU)
- **Biến môi trường**:
  ```bash
  export LAYA_DEVICE=cuda
  export LAYA_MODEL_PATH="/home/xinloihuy/Documents/AgentWazuh_dataset/laya_finetuned_typed_decisions"
  export LAYA_CONFIDENCE_THRESHOLD=0.60
  ```

---

## 3. Danh sách 9 Intent & Ánh xạ Workflow

| Intent Laya | Ý nghĩa vận hành | Workflow AgentWazuh định tuyến | Cơ chế kiểm soát bảo mật |
| :--- | :--- | :--- | :--- |
| `stats` | Tổng hợp số đếm, phân bố, top, báo cáo, xu hướng 24h | OpenSearch Aggregations / Wazuh Alert Stats Ground-Truth | Ngăn chặn LLM hallucinate số liệu. |
| `investigate` | Triage, phân tích bằng chứng IP, alert, incident, log | Investigation Pipeline với Snapshot, Evidence Grounding & PI | Chỉ nhận bằng chứng xác thực trong scope. |
| `create_rule` | Soạn/sửa/thử detection rule hoặc decoder | LangGraph StateGraph Sandbox HITL (`config_form_graph`) | Chỉ tạo bản nháp, bắt buộc operator ấn "Duyệt & Áp dụng". |
| `wazuh_lookup` | Tra cứu dữ liệu thực tế: Agent status, Rule ID, version | Ground-Truth Wazuh REST API / Local Knowledge Base | 0 LLM hallucination, tra cứu tức thì <1ms. |
| `configure` | Cấu hình hệ thống, ossec.conf, tích hợp | LangGraph StateGraph Config Form với validation & review | Không tự ý ghi file cấu hình. |
| `case_management`| Tạo/đóng gói/chuyển hồ sơ sự cố (Jira, TheHive) | Case Management Pipeline / Webhook Notifier | Yêu cầu xác nhận đích và snapshot ID. |
| `response_action`| Hành động phản ứng: block IP, cô lập host, restart | **HITL Authorization Guard** | **Chặn thực thi tự động qua chat**; yêu cầu Approval ID qua Active Response tab. |
| `support` | Hướng dẫn troubleshooting, giải thích khái niệm, chào hỏi | Local Wazuh Knowledge Base (0 token) / Helpful Guidance | Không can thiệp hay thay đổi hệ thống. |
| `out_of_scope` | Câu hỏi ngoài SOC, SIEM, Wazuh, an toàn thông tin | **Hard Scope Guard** | Từ chối ngay lập tức, không gọi LLM/external tool. |

---

## 4. Kiến trúc Thành phần (Architecture)

```text
Người dùng (Web Dashboard / Telegram Bridge)
               │
               ▼
     Laya Intent Router (Singleton, CUDA accelerated)
         ├── Thành công & Confidence >= 0.60 ────► 9 Intent chuẩn
         └── Lỗi / Thiếu model / Confidence thấp ─► Fallback (services/chat_intent.py)
               │
               ├─────────────────────────────────────────┐
               ▼                                         ▼
      [create_rule / configure]                 [response_action]
               │                                         │
               ▼                                         ▼
   LangGraph HITL Form Sandbox                  HITL Safety Guard
  (collect -> dry_run -> approval)         (Yêu cầu Approval Token / UI)
               │
               ├─────────────────────────────────────────┐
               ▼                                         ▼
      [wazuh_lookup / stats]                     [investigate / support]
               │                                         │
               ▼                                         ▼
   Wazuh REST API Ground Truth               SoLPi Observation Package
   (100% chính xác, 0 hallucination)        + PI AI Reasoning & Evidence Chain
```

---

## 5. Nguyên tắc An toàn & Fail-safe

1. **Singleton & Warmup**:
   - `get_laya_agent()` quản lý singleton với thread lock (`threading.Lock()`), chỉ nạp model 1 lần duy nhất khi khởi động.
   - Cơ chế warm-up tự động chạy 1 dummy inference ngay khi nạp để cache CUDA kernels.
2. **Fail-Safe Fallback**:
   - Nếu đường dẫn checkpoint không tồn tại, lỗi CUDA Out-Of-Memory, hoặc thư viện thiếu, hệ thống ghi log warning và tự động chuyển về router xác định (`services/chat_intent.py`).
   - Server không bao giờ bị gián đoạn hay sập tiến trình vì lỗi model.
3. **Hard Scope Guard**:
   - Khi dự đoán là `out_of_scope`, hệ thống lập tức trả về thông điệp chính sách SOC mà không gọi API LLM tốn token hay kích hoạt tool.
4. **HITL Authorization**:
   - `response_action` bắt buộc có sự can thiệp và phê duyệt của người vận hành.
   - Nhãn dự đoán chỉ mang tính phân loại ý định của người dùng, không bao giờ được coi là quyền hạn (permission) để tự động thực thi.

---

## 6. Khởi động & Kiểm thử

Chạy ứng dụng trong 1 lệnh duy nhất:
```bash
./start_agentwazuh.sh
```

Chạy test suite kiểm thử tích hợp:
```bash
/home/xinloihuy/Documents/AgentWazuh_dataset/laya_venv/bin/python3 -m unittest tests/test_laya_intent_router.py
```
