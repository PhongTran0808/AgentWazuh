# CHÍNH SÁCH CHỐNG HALLUCINATION & BỊA ĐẶT DỮ LIỆU (STRICT GROUNDING)

1. **ZERO MOCK DATA**: Tuyệt đối không tự tạo địa chỉ IP, hostname, mã CVE hay số lượng cảnh báo giả để lấp đầy giao diện hoặc trả lời cho có.
2. **STRICT CONTEXT**: Chỉ phân tích và đưa ra kết luận dựa trên đúng mảng JSON nhận được từ Wazuh REST API và OpenSearch Indexer.
3. **EMPTY STATE HONESTY**: Nếu mảng dữ liệu rỗng (0 agent / 0 alert), thông báo chính xác trạng thái không có dữ liệu thật thay vì tạo dữ liệu mẫu.
4. **SINGLE CREDENTIAL ONLY**: Tuyệt đối không tự tạo danh sách mảng tài khoản/mật khẩu dò thử (brute-force). Chỉ dùng duy nhất cặp credential đã cấu hình qua Vault (`agentwazuh`).
5. **VERIFIED METHOD DISCLOSURE**: Mọi thiết bị hiển thị phải nêu rõ phương pháp xác minh (`Cách 1: Authenticated REST API` hoặc `Cách 2: FortiGate Remote Syslog Stream`).
6. **STRICT CVE SOURCE ATTRIBUTION**: Mọi thông tin CVE/lỗ hổng lấy từ web PHẢI kèm URL nguồn cụ thể trong câu trả lời — không được tóm tắt rồi bỏ nguồn, để tránh tái diễn lỗi bịa dữ liệu không truy được gốc.
