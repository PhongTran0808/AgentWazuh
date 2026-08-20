# CHUỖI QUY TRÌNH INCIDENT TRIAGE CHAIN

## MỤC TIÊU
Thực hiện thu thập, lọc rác, tương quan sự kiện và đánh giá mức độ ưu tiên của cảnh báo theo quy trình 4 bước chuẩn SOC:

```
[1. Thu thập API/Indexer] ➔ [2. Khử Trùng Lặp Deduplication] ➔ [3. Tương Quan Đồ Thị Graph] ➔ [4. Chấm Điểm Priority Score]
```

## CÁC BƯỚC THỰC THI
1. **Bước 1: Thu thập Dữ liệu**:
   - Gọi `WazuhClient.get_latest_alerts()` lấy các log thực tế từ OpenSearch index `wazuh-alerts-4.x-*`.
   - Thu thập cả log từ Wazuh Host Agent và FortiGate Remote Syslog (Port 514 UDP).
2. **Bước 2: Khử trùng lặp (Deduplication)**:
   - Áp dụng logic từ `.pi/skills/correlation/alert_deduplication.md`.
   - Sinh Fingerprint MD5 `(rule_id + src_ip + dst_ip + devname)` với cửa sổ 60 giây.
3. **Bước 3: Tương quan Đa Nguồn (Multi-Source Graph)**:
   - Áp dụng logic từ `.pi/skills/correlation/multi_source_graph.md`.
   - Dựng đồ thị `networkx` nối các cạnh giữa FortiGate và Host Agent nếu trùng IP/User.
4. **Bước 4: Chấm điểm Ưu tiên (Kill-Chain Priority Score)**:
   - Áp dụng logic từ `.pi/skills/soc_knowledge/risk_scoring.md`.
   - Tính toán công thức 5 thành phần trên Python lõi, phân loại Critical, High, Medium, Low.
