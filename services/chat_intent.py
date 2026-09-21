"""Deterministic intent and response-style routing for the SOC chat."""

from __future__ import annotations

import re
from typing import Dict


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

