# SKILL: MITRE ATT&CK MAPPER

## NGUYÊN LÝ ÁNH XẠ
Tự động đối chiếu mã Wazuh Rule ID hoặc thông tin cảnh báo FortiGate với Ma trận MITRE ATT&CK chuẩn:

## BẢNG ÁNH XẠ MẪU CHÍNH TẮC
- **Rule 5716 / 5760 (SSH Authentication Failed)**:
  - Tactic: `Credential Access`
  - Technique: `T1110 - Brute Force`
- **Rule 100101 (FortiGate Connection Denied)**:
  - Tactic: `Reconnaissance`
  - Technique: `T1595 - Active Scanning`
- **Rule 100104 (FortiGate Attack Detected)**:
  - Tactic: `Initial Access` / `Exploitation`
  - Technique: `T1190 - Exploit Public-Facing Application`
- **Rule 5501 (PAM Session Opened)**:
  - Tactic: `Privilege Escalation` / `Persistence`
  - Technique: `T1078 - Valid Accounts`
