# SKILL: REAL NETWORK TOPOLOGY VISUALIZATION

## NGUYÊN TẮC VẼ SƠ ĐỒ MẠNG THẬT
- **Zero Hallucination**: Chỉ vẽ các thiết bị có thật trong kết quả API `GET /agents` của Wazuh Manager hoặc trong mảng alert Syslog thực tế.
- **Phân loại Node**:
  1. `[Wazuh Manager]` (192.168.1.248) - SIEM Central Core Node.
  2. `[Endpoint Agent]` (10.10.10.2 - Ubuntu-Agent) - Active Host Agent Node.
  3. `[Syslog Gateway]` (FortiGate Firewall) - Network Integration Node.

## ĐỊNH DẠNG SƠ ĐỒ MERMAID CHUẨN
```mermaid
graph TD
    Attacker[🌐 Internet / Remote Attacker] -->|Port 514 Syslog / Attack| FG[🛡️ FortiGate-VM64 Firewall]
    FG -->|Deny Connection| Web[🖥️ DMZ Web Server - Ubuntu-Agent 10.10.10.2]
    Web -->|Wazuh Agent Active Event| WM[🔒 Wazuh Manager 192.168.1.248]
    FG -->|Remote Syslog Event| WM
```
