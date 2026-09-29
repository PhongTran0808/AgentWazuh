"""Deterministic intent and response-style routing for the SOC chat."""

from __future__ import annotations

import re
from typing import Dict

SECURITY_SCOPE_MARKERS = (
    # Wazuh/SIEM and SOC vocabulary
    "wazuh", "siem", "soc", "opensearch", "elasticsearch", "agent", "rule", "alert",
    "log", "rest api", "mitre", "ioc", "incident", "security", "cyber", "cybersecurity",
    "firewall", "ids", "ips", "endpoint", "edr", "xdr", "threat", "malware", "ransomware",
    "phishing", "brute force", "vulnerability", "cve", "file integrity", "fim",
    # Vietnamese security vocabulary
    "an ninh", "bảo mật", "an toàn thông tin", "tấn công", "sự cố", "cảnh báo", "nhật ký",
    "mã độc", "virus", "lỗ hổng", "xác thực", "phân quyền", "đặc quyền", "giám sát",
    "điều tra", "truy vết", "phát hiện xâm nhập", "máy chủ", "thiết bị", "mạng máy tính",
)

CONTEXTUAL_FOLLOWUP_MARKERS = (
    "cảnh báo trên", "log trên", "alert trên", "rule trên", "sự cố trên", "điều này", "cái này",
    "nó là gì", "nó có nghĩa", "vừa nói", "vừa rồi", "ở trên", "this", "that", "above",
)


def is_security_related_query(query: str) -> bool:
    """Return whether the current query is within AgentWazuh's security scope."""
    text = (query or "").strip().lower()
    return bool(text) and any(
        re.search(rf"(?<!\w){re.escape(marker)}(?!\w)", text, re.IGNORECASE)
        for marker in SECURITY_SCOPE_MARKERS
    )


def is_contextual_security_followup(query: str) -> bool:
    """Allow short references to an already selected alert/security topic."""
    text = (query or "").strip().lower()
    return len(text) <= 120 and any(marker in text for marker in CONTEXTUAL_FOLLOWUP_MARKERS)


def classify_chat_intent(query: str) -> Dict[str, str]:
    text = (query or "").strip().lower()

    # 1. Greetings & bot capabilities
    if text in {"hi", "hello", "chào", "chào bạn", "alo", "help", "trợ giúp", "bạn là ai", "bạn làm được gì"}:
        return {"intent": "greeting", "format": "friendly_capabilities"}

    # 2. Rule configuration & HITL form requests
    if any(k in text for k in ("tạo rule", "viết rule", "rule xml", "cấu hình rule", "thêm rule", "sửa rule")):
        return {"intent": "rule_configuration", "format": "guided_steps_and_hitl_form"}

    # 3. How-to procedural guidance
    if any(k in text for k in ("làm thế nào", "cách nào", "hướng dẫn", "how to", "các bước", "làm sao để", "thiết lập", "cài đặt", "khởi động lại", "restart")):
        return {"intent": "how_to", "format": "numbered_procedure"}

    # 4. Explanations of concepts, rules, alerts, logs
    # E.g. "giải thích alert 5710", "ý nghĩa của rule này", "alert là gì", "khái niệm"
    if any(k in text for k in ("giải thích", "ý nghĩa", "là gì", "định nghĩa", "khái niệm", "tìm hiểu")):
        return {"intent": "wazuh_explanation", "format": "concept_then_example"}

    # 5. Metrics, statistics, and charts
    if any(k in text for k in ("thống kê", "bao nhiêu", "số lượng", "tổng số", "tỷ lệ", "phân bố", "top", "biểu đồ")):
        return {"intent": "metrics", "format": "compact_table_or_chart"}

    # 6. Specific investigation / Incident triage
    # Specific alert ID, incident ID, or clear investigation intent
    has_specific_id = bool(re.search(r"\b(inc-[a-f0-9]{4,16}|alert\s+[a-z0-9_\-]+)\b", text, re.I))
    is_investigate_action = any(k in text for k in ("điều tra", "phân tích sự cố", "phân tích nhóm sự cố", "phân tích alert", "truy vết", "triage", "investigate", "tấn công", "brute force", "ransomware", "mitre"))
    if has_specific_id or is_investigate_action:
        return {"intent": "investigation", "format": "soc_briefing"}

    # 7. General Wazuh system terms
    if any(k in text for k in ("agent", "wazuh manager", "opensearch", "syslog", "rest api", "log", "rule", "alert", "cảnh báo")):
        return {"intent": "wazuh_explanation", "format": "concept_then_example"}

    return {"intent": "general", "format": "direct_answer"}
