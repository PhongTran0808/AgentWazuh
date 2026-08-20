# CHUỖI QUY TRÌNH RULE BUILDER CHAIN (HITL)

## MỤC TIÊU
Thực hiện tiếp nhận yêu cầu từ SOC Analyst, tạo cấu hình Rule XML nháp, chạy thử nghiệm Sandbox Dry-Run và hiển thị Thẻ Form Tương Tác (Generative UI Card) để chờ phê duyệt theo quy trình HITL:

```
[1. Tiếp nhận Yêu cầu] ➔ [2. Sinh XML Rule Nháp] ➔ [3. Chạy Sandbox Dry-Run] ➔ [4. Xuất Card Form HITL]
```

## CÁC BƯỚC THỰC THI
1. **Bước 1: Tiếp nhận & Phân tích Yêu cầu**:
   - Trích xuất tham số: Tên Rule, Pattern khớp log, Tần suất xuất hiện (frequency), Khung thời gian (timeframe), Mức độ cảnh báo (level).
2. **Bước 2: Sinh Cấu Trúc Rule XML**:
   - Tuân thủ schema từ `.pi/skills/wazuh_engine/rule_generator.md`.
   - Cấu hình ID nằm trong dải Rule tự định nghĩa (`100100` - `100999`).
3. **Bước 3: Chạy Kiểm Thử Sandbox Dry-Run**:
   - Gọi `dry_run_rule()` kiểm tra khả năng khớp trên mảng log lịch sử thực tế mà không ảnh hưởng máy chủ Wazuh thật.
4. **Bước 4: Xuất Thẻ Thao Tác Interactive Form Card**:
   - Tuân thủ schema từ `.pi/skills/wazuh_engine/hitl_form_schema.md`.
   - Trả về payload JSON `CONFIG_FORM` với đầy đủ nút bấm "Duyệt Áp Dụng vào Wazuh" và "Hủy Bỏ".
