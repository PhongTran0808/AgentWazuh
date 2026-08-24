# CHUỖI QUY TRÌNH INCIDENT TRIAGE CHAIN (TINHGỌN OUTPUT PHÂN TÍCH SỰ CỐ)

## MỤC TIÊU
Thực hiện thu thập, tương quan sự kiện và tạo báo cáo **SOC Incident Briefing** tối giản, trực quan, đi thẳng vào hành động cho Analyst.

## ĐỊNH DẠNG OUTPUT BẮT BUỘC (CHỈ GỒM 3 PHẦN CỐT LÕI)

### Phần 1: Thông tin Trọng tâm & Đánh giá Rủi ro (Quick Verdict)
- **Tên sự cố**: [Mô tả ngắn gọn]
- **Mức độ nguy hiểm**: Level X ([Critical / High / Medium / Low]) | **Điểm rủi ro (Risk Score)**: X/100
- **MITRE ATT&CK**: [ID - Tên kỹ thuật] ([Tactic])
- **Đối tượng liên quan**: `IP Nguồn (Attacker)` ➔ `Thiết bị / Tài khoản Đích`

### Phần 2: Chuỗi Sự kiện Thực tế (Attack Timeline & Entity Correlation)
- **Luồng tấn công**: Sơ đồ mũi tên ngắn gọn (hoặc khối `mermaid` flowchart):
  `🌐 [IP Nguồn] ➔ 🖥️ [Target Host: User]`
- **Bảng tổng hợp sự kiện log liên quan**:
  | Timestamp | Rule ID | Level | Nội dung tóm tắt | User / Port |
  |---|---|---|---|---|
  | YYYY-MM-DD HH:MM:SS | 5710 | 5 | Failed login attempt | admin/root |
  | YYYY-MM-DD HH:MM:SS | 40112 | 12 | Multiple auth failures followed by success | root |

### Phần 3: Đề xuất Xử lý Ngay (SOC Action Playbook)
- Liệt kê **tối đa 3 - 4 hành động khẩn cấp**:
  1. [Hành động 1: Cách ly host / Khóa tài khoản]
  2. [Hành động 2: Block IP nguồn trên Firewall / FortiGate]
  3. [Hành động 3: Đổi mật khẩu & Bật xác thực đa yếu tố MFA]
  4. [Hành động 4: Đánh giá log chi tiết sau đăng nhập]

---

## RÀNG BUỘC CẮT BỎ (NEGATIVE CONSTRAINTS)
- **CẮT BỎ TOÀN BỘ**: Các văn bản giải thích lý thuyết workflow SOC ("Bước 1: Thu thập Dữ liệu...", "Bước 2: Khử trùng lặp...", "Quá trình deduplication...", "Bước 3: Tương quan...").
- **CẮT BỎ**: Các câu tuyên bố như "Nguồn dữ liệu: 100% thực tế từ Wazuh Server...".
- **PHONG CÁCH**: Ngắn gọn, scannable, ưu tiên Bảng Markdown và Bullet Points.
