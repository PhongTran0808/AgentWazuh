"""Laya Intent Classification & Active Routing Adapter for AgentWazuh.

Provides singleton-managed inference for the fine-tuned Laya checkpoint,
with automatic CUDA acceleration, strict fail-safe fallback to deterministic
keyword matching, confidence threshold guarding, and standard 9-intent taxonomy.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

from services.chat_intent import (
    classify_chat_intent as deterministic_classify_chat_intent,
    is_contextual_security_followup,
    is_security_related_query,
)

logger = logging.getLogger("AgentWazuhLayaRouter")

# Standard 9 intents supported by the fine-tuned Laya checkpoint
LAYA_INTENTS: Tuple[str, ...] = (
    "stats",
    "investigate",
    "create_rule",
    "wazuh_lookup",
    "configure",
    "case_management",
    "response_action",
    "support",
    "out_of_scope",
)

# Intent criteria schema aligned with training dataset
LAYA_QUESTIONS: Dict[str, Any] = {
    "intent": {
        "type": "choice",
        "instructions": (
            "Chọn đúng mục tiêu chính của người dùng để định tuyến yêu cầu trong AgentWazuh. "
            "Phân loại theo việc người dùng muốn hệ thống làm, không chỉ theo từ khóa/chủ đề. "
            "Nếu câu hỏi yêu cầu phân tích bằng chứng cụ thể, ưu tiên investigate; "
            "nếu yêu cầu thay đổi hoặc thực thi hành động, ưu tiên nhãn tương ứng và không suy ra quyền phê duyệt."
        ),
        "criteria": {
            "stats": (
                "Yêu cầu số liệu tổng hợp hoặc xu hướng: số lượng/tổng số, tỷ lệ, phân bố severity, "
                "top IP/rule/agent, biểu đồ hay báo cáo trong một khoảng thời gian. "
                "Ví dụ: '24 giờ qua có bao nhiêu alert mức cao?'"
            ),
            "investigate": (
                "Yêu cầu phân tích, giải thích theo bằng chứng, triage hoặc threat hunting một đối tượng/sự kiện cụ thể "
                "như IP, host, tài khoản, alert, log hay incident; bao gồm truy vết và tương quan sự kiện. "
                "Ví dụ: 'Điều tra IP này' hoặc 'Phân tích incident INC-...'. "
                "Không dùng cho tra cứu thuần túy tên/trạng thái/mô tả một bản ghi."
            ),
            "create_rule": (
                "Yêu cầu tạo, viết, sửa, kiểm thử/dry-run hoặc tinh chỉnh Wazuh detection rule/decoder. "
                "Đây là yêu cầu soạn thảo/kiểm thử nội dung phát hiện, không đồng nghĩa với quyền áp dụng cấu hình."
            ),
            "wazuh_lookup": (
                "Yêu cầu tra cứu dữ liệu hiện thời hoặc một bản ghi cụ thể từ Wazuh/AgentWazuh mà không cần điều tra nguyên nhân: "
                "trạng thái/phiên bản Manager, danh sách hoặc trạng thái Agent/thiết bị, định nghĩa Rule ID, "
                "inventory, topology hay trạng thái kết nối. "
                "Nếu người dùng yêu cầu phân tích ý nghĩa/nguy cơ từ alert hoặc chuỗi log, chọn investigate."
            ),
            "configure": (
                "Yêu cầu hướng đến việc thay đổi/cập nhật cấu hình hệ thống hoặc Wazuh, "
                "ví dụ settings, kết nối/API, tích hợp, agent/configuration hay cấu hình Manager. "
                "Nếu chỉ hỏi cách làm hoặc cần giải thích, chọn support; nếu cấu hình là rule/decoder detection, chọn create_rule. "
                "Nhãn này không phải là phê duyệt để ghi hoặc áp dụng thay đổi."
            ),
            "case_management": (
                "Yêu cầu tạo hoặc đóng gói hồ sơ/case sự cố để theo dõi hay chuyển tới Case Management/Webhook "
                "(ví dụ TheHive/Jira). Phân biệt với investigate: phân tích incident là investigate, "
                "còn tạo/gửi hồ sơ là case_management."
            ),
            "response_action": (
                "Yêu cầu thực hiện hoặc khởi chạy hành động phản ứng có tác động lên hệ thống/thiết bị/dịch vụ, "
                "ví dụ block IP, cô lập Agent, active response, restart Manager hoặc áp dụng cấu hình đã duyệt. "
                "Phân loại ý định không phải là sự cho phép thực thi; luôn cần kiểm tra quyền và quy trình HITL."
            ),
            "support": (
                "Chào hỏi, hỏi khả năng của trợ lý, giải thích khái niệm/tính năng Wazuh hoặc hướng dẫn vận hành/cấu hình "
                "chung chỉ mang tính tư vấn. Bao gồm troubleshooting và câu hỏi 'là gì/cách làm thế nào' "
                "khi không yêu cầu hệ thống tra cứu trạng thái thực tế hay thực hiện thay đổi."
            ),
            "out_of_scope": (
                "Yêu cầu hoàn toàn không liên quan đến SOC, an ninh mạng, Wazuh hoặc vận hành AgentWazuh, "
                "như nội dung đời sống, sáng tác hay lập trình không phục vụ bảo mật."
            ),
        },
    }
}

# Compatibility mapping to legacy formats for downstream UI and prompt builders
LEGACY_FORMAT_MAP: Dict[str, str] = {
    "stats": "compact_table_or_chart",
    "investigate": "soc_briefing",
    "create_rule": "guided_steps_and_hitl_form",
    "wazuh_lookup": "concept_then_example",
    "configure": "guided_steps_and_hitl_form",
    "case_management": "soc_briefing",
    "response_action": "soc_briefing",
    "support": "friendly_capabilities",
    "out_of_scope": "direct_answer",
}

# Compatibility mapping from Laya intent to legacy chat_intent categories
LEGACY_INTENT_MAP: Dict[str, str] = {
    "stats": "metrics",
    "investigate": "investigation",
    "create_rule": "rule_configuration",
    "wazuh_lookup": "wazuh_explanation",
    "configure": "rule_configuration",
    "case_management": "investigation",
    "response_action": "investigation",
    "support": "how_to",
    "out_of_scope": "general",
}

DEFAULT_MODEL_PATH = "/home/xinloihuy/Documents/AgentWazuh_dataset/laya_finetuned_typed_decisions"
DEFAULT_CONFIDENCE_THRESHOLD = 0.60

_AGENT_SINGLETON = None
_AGENT_LOCK = threading.Lock()
_INIT_FAILED = False


def _get_configured_device() -> str:
    """Return device preference, checking CUDA availability."""
    configured = os.getenv("LAYA_DEVICE", "").strip().lower()
    if configured:
        return configured
    try:
        import torch
        return "cuda" if torch.cuda.is_available() else "cpu"
    except Exception:
        return "cpu"


def get_laya_agent() -> Optional[Any]:
    """Lazy-load and return the singleton Laya agent instance with thread safety.

    Returns None if the model cannot be loaded, enabling transparent fallback.
    """
    global _AGENT_SINGLETON, _INIT_FAILED
    if _AGENT_SINGLETON is not None:
        return _AGENT_SINGLETON
    if _INIT_FAILED:
        return None

    with _AGENT_LOCK:
        if _AGENT_SINGLETON is not None:
            return _AGENT_SINGLETON
        if _INIT_FAILED:
            return None

        model_path = os.getenv("LAYA_MODEL_PATH", DEFAULT_MODEL_PATH).strip()
        if not os.path.exists(model_path):
            logger.warning(
                "Laya model path không tồn tại: %s. Chuyển sang fallback router.",
                model_path,
            )
            _INIT_FAILED = True
            return None

        device = _get_configured_device()
        try:
            import laya

            logger.info("Đang nạp Laya checkpoint từ '%s' trên thiết bị '%s'...", model_path, device)
            t0 = time.perf_counter()
            agent = laya.load(model_path, device=device)
            load_ms = (time.perf_counter() - t0) * 1000

            # Warm-up inference to compile/cache CUDA kernels
            try:
                agent.predict({"message": "ping"}, LAYA_QUESTIONS)
                logger.info("Laya model khởi tạo thành công (nạp: %.1f ms, device: %s).", load_ms, device)
            except Exception as warmup_err:
                logger.warning("Warmup Laya gặp lỗi nhẹ: %s (bỏ qua)", warmup_err)

            _AGENT_SINGLETON = agent
            return _AGENT_SINGLETON
        except Exception as exc:
            logger.exception("Không thể nạp Laya model (%s): %s. Sẽ dùng deterministic fallback.", model_path, exc)
            _INIT_FAILED = True
            return None


def route_intent(
    query: str,
    confidence_threshold: Optional[float] = None,
    allow_fallback: bool = True,
) -> Dict[str, Any]:
    """Classify user intent using the Laya model with automatic fallback.

    Args:
        query: User text input.
        confidence_threshold: Minimum confidence required (default: 0.60).
        allow_fallback: If True, falls back to deterministic router on error or low confidence.

    Returns:
        Dict with keys:
            - intent: One of the 9 LAYA_INTENTS
            - confidence: float score between 0.0 and 1.0
            - probabilities: dict of class probabilities
            - format: legacy response format string
            - legacy_intent: legacy intent string
            - fallback_used: bool indicating if fallback was used
            - model_used: string descriptor of the engine
            - latency_ms: float execution time in milliseconds
    """
    clean_query = (query or "").strip()
    threshold = (
        confidence_threshold
        if confidence_threshold is not None
        else float(os.getenv("LAYA_CONFIDENCE_THRESHOLD", DEFAULT_CONFIDENCE_THRESHOLD))
    )

    # Empty or whitespace queries
    if not clean_query:
        return {
            "intent": "support",
            "confidence": 1.0,
            "probabilities": {"support": 1.0},
            "format": "friendly_capabilities",
            "legacy_intent": "greeting",
            "fallback_used": True,
            "model_used": "empty_input_fallback",
            "latency_ms": 0.0,
        }

    agent = get_laya_agent()
    if agent is not None:
        t0 = time.perf_counter()
        try:
            with _AGENT_LOCK:
                prediction = agent.predict({"message": clean_query[:2000]}, LAYA_QUESTIONS)
            latency_ms = (time.perf_counter() - t0) * 1000

            answer = prediction.get("answers", {}).get("intent", {})
            choice = answer.get("choice")
            probs = answer.get("probabilities", {})
            raw_conf = answer.get("confidence")
            ans_conf = answer.get("answer_confidence")
            prob_choice = probs.get(choice, 0.0)

            # Robust confidence computation taking into account calibrated and raw probabilities
            confidence = max(
                float(raw_conf or 0.0),
                float(ans_conf or 0.0),
                float(prob_choice or 0.0)
            )

            # Ensure predicted choice is valid
            if choice in LAYA_INTENTS and confidence >= threshold:
                legacy_fmt = LEGACY_FORMAT_MAP.get(choice, "direct_answer")
                legacy_int = LEGACY_INTENT_MAP.get(choice, "general")
                device = _get_configured_device()
                return {
                    "intent": choice,
                    "confidence": round(confidence, 4),
                    "probabilities": {k: round(v, 4) for k, v in probs.items()},
                    "format": legacy_fmt,
                    "legacy_intent": legacy_int,
                    "fallback_used": False,
                    "model_used": f"laya_finetuned ({device})",
                    "latency_ms": round(latency_ms, 2),
                }

            logger.info(
                "Laya dự đoán '%s' với confidence %.2f < ngưỡng %.2f -> Kích hoạt fallback.",
                choice,
                confidence,
                threshold,
            )
        except Exception as exc:
            logger.warning("Lỗi suy luận Laya cho query '%s': %s. Kích hoạt fallback.", clean_query[:40], exc)

    if not allow_fallback:
        return {
            "intent": "support",
            "confidence": 0.0,
            "probabilities": {},
            "format": "direct_answer",
            "legacy_intent": "general",
            "fallback_used": True,
            "model_used": "none",
            "latency_ms": 0.0,
        }

    # Deterministic fallback router
    t0 = time.perf_counter()
    legacy_res = deterministic_classify_chat_intent(clean_query)
    fallback_latency = (time.perf_counter() - t0) * 1000
    legacy_int = legacy_res.get("intent", "general")
    legacy_fmt = legacy_res.get("format", "direct_answer")

    # Map legacy intent back to 9 standard LAYA_INTENTS
    reverse_map: Dict[str, str] = {
        "greeting": "support",
        "how_to": "support",
        "rule_configuration": "create_rule",
        "wazuh_explanation": "wazuh_lookup",
        "metrics": "stats",
        "investigation": "investigate",
        "general": "support" if is_security_related_query(clean_query) else "out_of_scope",
    }
    mapped_laya_intent = reverse_map.get(legacy_int, "support")

    return {
        "intent": mapped_laya_intent,
        "confidence": 0.85,
        "probabilities": {mapped_laya_intent: 0.85},
        "format": legacy_fmt,
        "legacy_intent": legacy_int,
        "fallback_used": True,
        "model_used": "deterministic_chat_intent (fallback)",
        "latency_ms": round(fallback_latency, 2),
    }


def classify_chat_intent_laya(query: str) -> Dict[str, str]:
    """Drop-in replacement for classify_chat_intent with legacy format & intent."""
    res = route_intent(query)
    return {
        "intent": res.get("legacy_intent", "general"),
        "format": res.get("format", "direct_answer"),
        "laya_intent": res.get("intent", "support"),
        "confidence": str(res.get("confidence", 0.0)),
        "fallback_used": str(res.get("fallback_used", False)),
    }
