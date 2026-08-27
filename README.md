# 🛡️ AGENT WAZUH — SOC AI ASSISTANT & SECURITY CO-PILOT SYSTEM

## 📌 1. TỔNG QUAN ĐỀ TÀI & Ý TƯỞNG HỆ THỐNG

**AgentWazuh** là hệ thống Trợ lý An ninh Mạng AI (SOC AI Co-Pilot) hoạt động dựa trên mô hình **Multi-Agent AI**. Hệ thống kết nối trực tiếp với **Wazuh SIEM Manager** để giám sát, phân tích nhật ký (log), tự động tính toán điểm rủi ro (Risk Score & Health Score), phát hiện tấn công theo thời gian thực và đưa ra khuyến nghị phản ứng sự cố khẩn cấp.

---

## 🏗️ 2. KIẾN TRÚC VÀ CÁC THÀNH PHẦN HỆ THỐNG

### 2.1 Cổng dịch vụ (Ports)
- **Port 8080**: Giao diện SOC AI Assistant & REST API Core Backend (`core/server.py`).
- **Wazuh Manager REST API**: `https://192.168.1.201:55000` (hoặc `192.168.1.210:55000`).
  - **Tài khoản mặc định API**: User `wazuh`, Password `wazuh` (hoặc `admin` / `adminpassword`).

### 2.2 Các mô hình AI Agents (5 Agents phối hợp)
1. **Log Ingestion Agent**: Thu thập log sự kiện từ Wazuh Manager API (`/alerts`).
2. **Device Discovery & Inventory Agent**: Quản lý thiết bị đã biết (`config/known_devices.json`) và thiết bị mới phát hiện.
3. **Risk Scoring Agent**: Tính điểm Health Score (0-100) và Risk Score dựa trên mức độ nghiêm trọng (Alert Level 1-15) & Asset Criticality.
4. **Threat Intelligence Agent**: Phân tích hành vi tấn công (Brute Force, SSH Attack, Web Attack, Port Scan).
5. **Mitigation & SOC Action Agent**: Đề xuất kịch bản ngăn chặn khẩn cấp (Block IP, Isolation, Firewall Rule).

---

## 🚀 3. HƯỚNG DẪN KHỞI ĐỘNG HỆ THỐNG (RUNNING PROCEDURE)

### 3.1 Lệnh khởi động độc lập (Port 8080)
```bash
cd "/run/media/kweismann/Dir_D/Tiểu luận CN/AgentWazuh"
python3 server.py
```

### 3.2 Lệnh khởi động đồng thời cả 2 hệ thống AgentWazuh (8080) & SoDoMang (9090)
```bash
python3 /tmp/start_agentwazuh_and_sodomang.py
```

---

## ⚙️ 4. CẤU HÌNH HỆ THỐNG (SYSTEM SETTINGS)

File cấu hình đặt tại: `config/system_settings.json`
```json
{
  "wazuh_host": "192.168.1.201",
  "wazuh_port": 55000,
  "user": "wazuh",
  "password": "wazuh",
  "ping_interval": 15,
  "ping_retry": 3
}
```

File lưu danh sách thiết bị giám sát: `config/known_devices.json`

---

## 🛠️ 5. CÁC LỖI THƯỜNG GẶP VÀ CÁCH KHẮC PHỤC (TROUBLESHOOTING & KNOWN BUGS)

### 🔴 Lỗi 1: `HTTP 401 Unauthorized` khi gọi Wazuh REST API 55000
- **Nguyên nhân**: Mật khẩu API không chính xác hoặc Token hết hạn.
- **Khắc phục**: Wazuh 4.x sử dụng tài khoản `wazuh` / `wazuh` trên API cổng 55000 để lấy Bearer Token qua endpoint `POST /security/user/authenticate?raw=true`.

### 🔴 Lỗi 2: Agent báo `Never connected` trên Wazuh Dashboard
- **Nguyên nhân**:
  1. Chuỗi `key` trả về từ API `/agents/{id}/key` là dạng **Base64**. Nếu ghi trực tiếp vào `/var/ossec/etc/client.keys` mà không decode sẽ làm hỏng bắt tay SSL.
  2. File `/var/ossec/etc/ossec.conf` trong Agent bị lưu IP cũ (`172.16.175.145`).
- **Khắc phục chuẩn**:
  - Decode Base64 key trước khi ghi vào `/var/ossec/etc/client.keys`:
    ```python
    plain_key = base64.b64decode(b64_key).decode('utf-8').strip()
    ```
  - Cập nhật `<address>192.168.1.201</address>` trong `ossec.conf` và khởi động lại dịch vụ Agent.

### 🔴 Lỗi 3: `Duplicate agent name` khi chạy `agent-auth`
- **Nguyên nhân**: Tên Agent đã được đăng ký trước đó trên Manager REST API.
- **Khắc phục**: Sử dụng script lấy Key trực tiếp qua REST API thay vì chạy lại `agent-auth`, hoặc xóa Agent cũ qua DELETE `/agents?agents_list=...` trước khi đăng ký mới.
