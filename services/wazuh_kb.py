"""
Fast Local Wazuh SIEM Knowledge Base & Instant Answer Engine.
Loads modular handbook chapters from `config/wazuh_handbook/*.json` (each < 1000 lines)
and provides <1ms deterministic answers with SVG visual illustrations for SOC Analysts,
saving 100% LLM tokens on operational, UI, deployment, rule-writing, and troubleshooting queries.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
HANDBOOK_DIR = BASE_DIR / "config" / "wazuh_handbook"
LEGACY_KB_PATH = BASE_DIR / "config" / "wazuh_knowledge_base.json"

_KB_CACHE: Optional[Dict[str, Any]] = None
_KB_SIGNATURE: float = 0.0


def _compute_handbook_signature() -> float:
    sig = 0.0
    if HANDBOOK_DIR.exists():
        for f in sorted(HANDBOOK_DIR.glob("*.json")):
            try:
                sig += f.stat().st_mtime
            except OSError:
                pass
    if sig == 0.0 and LEGACY_KB_PATH.exists():
        try:
            sig = LEGACY_KB_PATH.stat().st_mtime
        except OSError:
            pass
    return sig


def load_wazuh_kb() -> Dict[str, Any]:
    """Load and merge all modular Wazuh handbook JSON chapters into RAM cache."""
    global _KB_CACHE, _KB_SIGNATURE
    sig = _compute_handbook_signature()
    if _KB_CACHE is not None and sig == _KB_SIGNATURE:
        return _KB_CACHE

    merged_topics: List[Dict[str, Any]] = []
    seen_ids = set()

    if HANDBOOK_DIR.exists():
        for chapter_file in sorted(HANDBOOK_DIR.glob("*.json")):
            try:
                data = json.loads(chapter_file.read_text(encoding="utf-8"))
                chapter_num = data.get("chapter", "")
                chapter_title = data.get("chapter_title", "")
                for topic in data.get("topics", []):
                    tid = topic.get("id")
                    if tid and tid not in seen_ids:
                        seen_ids.add(tid)
                        topic_copy = dict(topic)
                        topic_copy["chapter"] = chapter_num
                        topic_copy["chapter_title"] = chapter_title
                        topic_copy["source_file"] = f"config/wazuh_handbook/{chapter_file.name}"
                        merged_topics.append(topic_copy)
            except Exception:
                continue

    if not merged_topics and LEGACY_KB_PATH.exists():
        try:
            legacy = json.loads(LEGACY_KB_PATH.read_text(encoding="utf-8"))
            merged_topics = legacy.get("topics", [])
        except Exception:
            pass

    _KB_CACHE = {"topics": merged_topics}
    _KB_SIGNATURE = sig
    return _KB_CACHE


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def match_wazuh_kb_topic(query: str) -> Optional[Dict[str, Any]]:
    """
    Match a user query against structured Wazuh SIEM handbook topics.
    Returns the best matching topic dict if confidence is high, else None.
    """
    q = _normalize(query)
    if not q or len(q) < 4:
        return None

    # Do NOT intercept live incident investigations, explicit Rule ID lookups,
    # or live HITL rule-creation commands.
    if re.search(r"\binc-[a-f0-9]{4,16}\b", q):
        return None
    if re.search(r"\b(?:rule|quy tắc)\s+\d{3,6}\b", q) and "rule id 100000" not in q:
        return None
    is_howto_question = any(
        qw in q
        for qw in (
            "cách ",
            "làm sao",
            "làm thế nào",
            "như thế nào",
            "ở đâu",
            "hướng dẫn",
            "là gì",
            "trên wazuh",
            "trong wazuh",
        )
    )
    if not is_howto_question and any(
        cmd in q
        for cmd in (
            "phân tích sự cố",
            "phân tích nhóm sự cố",
            "phân tích alert",
            "tạo rule",
            "thêm rule",
            "sửa rule",
            "cấu hình rule",
            "mở form",
            "hủy form",
            "bao nhiêu agent",
            "danh sách agent",
            "danh sách thiết bị",
            "thống kê cảnh báo",
            "thống kê 24h",
            "báo cáo 24h",
            "báo cáo 24 giờ",
            "24 giờ qua",
            "24h qua",
        )
    ):
        return None

    kb = load_wazuh_kb()
    topics: List[Dict[str, Any]] = kb.get("topics", [])

    best_topic: Optional[Dict[str, Any]] = None
    best_score = 0

    for topic in topics:
        score = 0
        for kw in topic.get("keywords", []):
            kw_norm = _normalize(kw)
            if not kw_norm:
                continue
            if kw_norm in q:
                score += max(2, len(kw_norm.split())) * 3

        tid = topic.get("id", "")
        if tid == "ui_buttons_guide" and any(w in q for w in ("nút", "màn hình chính", "overview", "giao diện", "agents summary", "endpoint security", "threat intelligence", "security operations", "cloud security", "it hygiene")):
            score += 6
        elif tid == "wazuh_native_dashboard_menus" and any(w in q for w in ("menu", "thanh menu", "nút 3 gạch", "bên trái", "discover", "explore", "server management", "indexer management", "agents management")):
            score += 6
        elif tid == "add_device_agent" and any(w in q for w in ("thêm thiết bị", "cài agent", "cài đặt agent", "thêm agent", "thêm máy", "đăng ký agent", "thêm fortigate", "deploy new agent")):
            score += 6
        elif tid == "agent_groups_and_removal" and any(w in q for w in ("xóa agent", "gỡ bỏ agent", "agent.conf", "cấu hình tập trung", "đổi ip")):
            score += 6
        elif tid == "log_locations" and any(w in q for w in ("đọc log", "xem log", "log ở đâu", "nằm ở đâu", "ossec.log", "alerts.json", "ossec.conf", "events", "cách xem cảnh báo")):
            score += 6
        elif tid == "archives_logall_guide" and any(w in q for w in ("archives.json", "logall", "logall_json", "chưa khớp rule", "server logs")):
            score += 6
        elif tid == "troubleshooting_errors" and any(w in q for w in ("lỗi", "disconnected", "mất kết nối", "không lên log", "filebeat", "sửa lỗi", "khắc phục", "not ready yet", "0 cảnh báo", "hiện số 0")):
            score += 5
        elif tid == "wazuh_cli_cheatsheet" and any(w in q for w in ("lệnh wazuh", "câu lệnh", "cli", "cheatsheet", "bảng lệnh", "wazuh-control")):
            score += 6
        elif tid == "architecture_ports" and any(w in q for w in ("cổng", "port", "1514", "1515", "55000", "9200", "kiến trúc")):
            score += 5
        elif tid == "wazuh_daemons_explained" and any(w in q for w in ("daemon", "tiến trình", "wazuh-analysisd", "wazuh-remoted", "wazuh-modulesd", "wazuh-db")):
            score += 6
        elif tid == "custom_rules_decoders" and any(w in q for w in ("cách viết rule", "if_sid", "if_matched_sid", "cấp độ level", "level trong wazuh", "overwrite", "sửa rule", "custom rules", "manage rules files")):
            score += 5
        elif tid == "decoders_and_logtest" and any(w in q for w in ("decoder", "local_decoder", "wazuh-logtest", "ruleset test", "tách trường", "prematch")):
            score += 6
        elif tid == "fim_sca_active_response" and any(w in q for w in ("fim", "syscheck", "sca", "cis benchmark", "active response", "whodata", "vulnerability")):
            score += 5
        elif tid == "rest_api_and_opensearch_guide" and any(w in q for w in ("gọi api", "jwt token", "xóa index", "wazuh-alerts-4.x", "truy vấn opensearch", "api console", "dev tools")):
            score += 6

        if score > best_score:
            best_score = score
            best_topic = topic

    if best_topic and best_score >= 5:
        return best_topic
    return None


def render_wazuh_kb_answer(query: str, host: str = "127.0.0.1") -> Optional[Dict[str, Any]]:
    """
    Return a formatted markdown answer (with SVG illustration) and metadata
    if the query matches a local Wazuh Knowledge Base topic.
    """
    topic = match_wazuh_kb_topic(query)
    if not topic:
        return None

    clean_host = host if host and host not in ("", "N/A", "none", "null") else "127.0.0.1"
    markdown_text = str(topic.get("answer_markdown", "")).replace("{host}", clean_host)
    return {
        "topic_id": topic.get("id"),
        "title": topic.get("title"),
        "chapter": topic.get("chapter", ""),
        "source_file": topic.get("source_file", "config/wazuh_knowledge_base.json"),
        "image_url": topic.get("image_url"),
        "markdown": markdown_text,
        "quick_summary": topic.get("quick_summary", ""),
    }


def get_compact_kb_context(query: str) -> str:
    """
    Return a compact 2-line knowledge snippet to inject into LLM prompts
    when a complex hybrid question touches Wazuh concepts.
    """
    q = _normalize(query)
    kb = load_wazuh_kb()
    snippets: List[str] = []
    for topic in kb.get("topics", []):
        if any(_normalize(kw) in q for kw in topic.get("keywords", [])):
            snippets.append(f"- [{topic.get('title')}]: {topic.get('quick_summary')}")
    return "\n".join(snippets[:2])
