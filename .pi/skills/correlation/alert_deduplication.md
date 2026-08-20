# SKILL: ALERT DEDUPLICATION (KHỬ TRÙNG LẶP CẢNH BÁO)

## NGUYÊN LÝ VẬN HÀNH
Gộp các cảnh báo có cùng bản chất xảy ra liên tiếp trong cửa sổ thời gian ngắn (`dedup_window_seconds = 60s`) thành một bản ghi duy nhất để tránh bão log.

## THUẬT TOÁN FINGERPRINT
```python
raw_fingerprint = f"{rule_id}_{srcip}_{dstip}_{devname}"
fingerprint = hashlib.md5(raw_fingerprint.encode()).hexdigest()
```

## QUY TẮC GỘM
- Nếu alert mới có cùng `fingerprint` và `abs(time_new - time_old) <= 60s`:
  - Đóng gói chung vào bản ghi đã có.
  - Tăng biến đếm `occurrence_count += 1`.
  - Giữ lại timestamp của mốc thời gian sớm nhất.
