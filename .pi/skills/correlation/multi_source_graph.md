# SKILL: MULTI-SOURCE GRAPH CORRELATION (TƯƠNG QUAN ĐỒ THỊ ĐA NGUỒN)

## NGUYÊN LÝ VẬN HÀNH
Kết hợp thư viện `networkx` và `scikit-learn` để tự động xây dựng đồ thị liên kết cảnh báo từ 2 nguồn: **Wazuh Host Agent (DMZ Web Server)** và **FortiGate Remote Syslog (Port 514 UDP)**.

## QUY TRÌNH THỰC THI
1. **Node**: Mỗi alert là 1 Node trong đồ thị `G = nx.Graph()`.
2. **Edges**: Nối cạnh giữa 2 Node nếu thỏa mãn 1 trong 2 điều kiện:
   - **Shared Entity**: Dùng chung IP nguồn (`srcip`), IP đích (`dstip`) hoặc Username (`srcuser`/`dstuser`).
   - **Semantic Similarity**: Độ tương đồng TF-IDF Cosine Similarity giữa mô tả văn bản log `>= 0.65`.
3. **Cluster Component**: Sử dụng `nx.connected_components(G)` gom các nốt nối thành một `Incident Group` hoàn chỉnh.
