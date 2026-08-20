# CHUỖI QUY TRÌNH THREAT HUNTING CHAIN

## MỤC TIÊU
Điểu tra chuyên sâu hành vi của một IP, Hostname hoặc tài khoản người dùng theo Ma trận MITRE ATT&CK dựa hoàn toàn trên dữ liệu nhật ký thực tế:

```
[1. Truy vấn Dữ liệu IP/Host] ➔ [2. Ánh Xạ MITRE ATT&CK] ➔ [3. Dựng Sơ Đồ Mermaid] ➔ [4. Đề Xuất Khuyến Nghị SOC]
```

## CÁC BƯỚC THỰC THI
1. **Bước 1: Lọc Dữ liệu Đối tượng**:
   - Truy vấn toàn bộ log có liên quan tới IP/Host/User mục tiêu trong 24h qua.
2. **Bước 2: Ánh xạ MITRE ATT&CK**:
   - Tham chiếu với `.pi/skills/soc_knowledge/mitre_mapper.md` để xác định Tactic (Reconnaissance, Credential Access, Defense Evasion...) và Technique ID tương ứng (T1110, T1059...).
3. **Bước 3: Dựng Sơ Đồ Luồng Tấn Công**:
   - Tạo sơ đồ Mermaid (` ```mermaid `) mô tả trực quan đường đi của Hacker từ Gateway tới DMZ Web Server.
4. **Bước 4: Xuất Khuyến Nghị Phòng Thủ**:
   - Đưa ra playbook xử lý ứng cứu sự cố (Block IP trên FortiGate, Cô lập Agent, Đổi mật khẩu tài khoản).
