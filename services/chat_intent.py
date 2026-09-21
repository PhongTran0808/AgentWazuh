"""Deterministic intent and response-style routing for the SOC chat."""

from __future__ import annotations

from typing import Dict


def classify_chat_intent(query: str) -> Dict[str, str]:
    text = (query or "").strip().lower()
    if text in {"hi", "hello", "chào", "chào bạn", "help", "trợ giúp", "bạn là ai", "bạn làm được gì"}:
        return {"intent": "greeting", "format": "friendly_capabilities"}
    if any(k in text for k in ("tạo rule", "viết rule", "rule xml", "cấu hình rule", "thêm rule")):
        return {"intent": "rule_configuration", "format": "guided_steps_and_hitl_form"}
    if any(k in text for k in ("cách", "làm thế nào", "hướng dẫn", "how to", "thiết lập", "cài đặt", "restart", "khởi động")):
        return {"intent": "how_to", "format": "numbered_procedure"}
    if any(k in text for k in ("thống kê", "bao nhiêu", "số lượng", "top", "phân bố", "biểu đồ")):
        return {"intent": "metrics", "format": "compact_table_or_chart"}
    if any(k in text for k in ("alert", "cảnh báo", "incident", "sự cố", "tấn công", "brute", "ransomware", "mitre")):
        return {"intent": "investigation", "format": "soc_briefing"}
    if any(k in text for k in ("agent", "wazuh manager", "opensearch", "syslog", "api", "log", "rule")):
        return {"intent": "wazuh_explanation", "format": "concept_then_example"}
    return {"intent": "general", "format": "direct_answer"}

