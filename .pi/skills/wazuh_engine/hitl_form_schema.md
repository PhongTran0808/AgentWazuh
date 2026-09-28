# GENERATIVE UI FORM CONTRACT (HITL INTERACTIVE CARD SCHEMA)

Khi người dùng yêu cầu cấu hình hoặc tạo rule mới cho Wazuh, phản hồi bắt buộc kèm theo khối JSON Generative UI để hiển thị Thẻ Form Tương Tác cho SOC Analyst duyệt:

```json
```json:form
{
  "type": "CONFIG_FORM",
  "title": "⚙️ Phê Duyệt Cấu Hình Rule Mới (HITL Sandbox)",
  "form_data": {
    "rule_name": "Phát Hiện Tấn Công Brute Force SSH Tần Suất Cao",
    "match_pattern": "Failed password for root",
    "frequency": 5,
    "timeframe": 60,
    "level": 12,
    "draft_xml": "<group name=\"custom,\">\n  <rule id=\"100105\" level=\"12\" frequency=\"5\" timeframe=\"60\">\n    <if_matched_sid>5716</if_matched_sid>\n    <same_source_ip />\n    <description>Phát Hiện Tấn Công Brute Force SSH Tần Suất Cao</description>\n  </rule>\n</group>"
  },
  "sandbox_result": {
    "status": "PASS",
    "historical_matches": 14,
    "false_positive_rate": "0.0%"
  },
  "actions": [
    {
      "label": "✅ Duyệt & Áp dụng vào Wazuh Manager",
      "endpoint": "/api/wazuh/apply-rule",
      "method": "POST"
    },
    {
      "label": "❌ Hủy Bỏ",
      "action": "DISMISS"
    }
  ]
}
```
```
