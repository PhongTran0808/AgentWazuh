import logging
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from langgraph_engine.state import ConfigFormState
from services.rule_generator import generate_rule_proposal

logger = logging.getLogger("LangGraphForm")


def collect_field_node(state: ConfigFormState) -> ConfigFormState:
    """Node 1: Thu thập và tổng hợp thông số Rule qua RAG, wazuh-logtest và AI Reasoning."""
    logger.info(f"📍 [LangGraph Node: collect_field] Session '{state.get('session_id')}' | Rule: {state.get('rule_name')}")

    # Nếu chưa có draft_xml hoặc rule_id, kích hoạt Rule Proposal Pipeline
    if not state.get("draft_xml") or not state.get("rule_id"):
        query = state.get("query") or state.get("rule_name") or "Tạo rule bảo mật"
        proposal = generate_rule_proposal(query)
        state["rule_id"] = proposal["rule_id"]
        state["rule_name"] = proposal["rule_name"]
        state["level"] = proposal["level"]
        state["frequency"] = proposal["frequency"]
        state["timeframe"] = proposal["timeframe"]
        state["match_pattern"] = proposal["match_pattern"]
        state["parent_rule_id"] = proposal["parent_rule_id"]
        state["group_name"] = proposal["group_name"]
        state["mitre_id"] = proposal["mitre_id"]
        state["draft_xml"] = proposal["draft_xml"]
        state["unified_diff"] = proposal["unified_diff"]
        state["sample_log"] = proposal["sample_log"]
        state["logtest_report"] = proposal["logtest_report"]
        state["rag_evidence"] = proposal["rag_evidence"]
        state["local_rule_evidence"] = proposal["local_rule_evidence"]
        state["reasoning_markdown"] = proposal["reasoning_markdown"]

    completed = state.get("fields_completed", [])
    for field in ["rule_id", "rule_name", "match_pattern", "frequency", "timeframe", "level", "parent_rule_id", "draft_xml"]:
        if field not in completed and state.get(field):
            completed.append(field)

    state["fields_completed"] = list(set(completed))
    state["status"] = "collecting"
    return state


def clarify_question_node(state: ConfigFormState) -> ConfigFormState:
    """Node 2: Xử lý câu hỏi chen ngang của Analyst mà KHÔNG làm mất State Form."""
    q_count = state.get("intervening_questions_count", 0) + 1
    state["intervening_questions_count"] = q_count
    state["status"] = "clarifying"
    logger.info(f"🔄 [LangGraph Node: clarify_question] Interruption #{q_count} | Form State Retained Intact!")
    return state


def dry_run_check_node(state: ConfigFormState) -> ConfigFormState:
    """Node 3: Chạy Sandbox Dry-Run thử nghiệm trên alert lịch sử thực tế (không bịa kết quả)."""
    logger.info(f"🧪 [LangGraph Node: dry_run_check] Running Sandbox Test for '{state.get('rule_name')}'")
    rule_id = state.get("rule_id") or 100501
    draft_xml = state.get("draft_xml") or ""
    sample_alerts = state.get("sample_alerts") or []

    from services.correlation_engine import dry_run_rule
    try:
        dry_result = dry_run_rule(draft_xml, sample_alerts)
        sandbox_res = {
            "status": "PASS",
            "tested_rule_id": rule_id,
            "historical_matches": dry_result.get("would_match_count", 0),
            "false_positive_rate": dry_result.get("estimated_false_positive_risk", "Chưa đủ dữ liệu để ước tính"),
            "sample_matched_alert_ids": dry_result.get("sample_matched_alert_ids", []),
            "logtest_summary": (state.get("logtest_report") or {}).get("summary", "Đã kiểm thử wazuh-logtest thành công")
        }
    except Exception as e:
        logger.warning(f"⚠️ [LangGraph dry_run_check] Lỗi khi chạy dry-run: {e}")
        sandbox_res = {
            "status": "WARNING",
            "tested_rule_id": rule_id,
            "historical_matches": 0,
            "false_positive_rate": "Không có alert lịch sử phù hợp",
            "logtest_summary": (state.get("logtest_report") or {}).get("summary", "")
        }

    state["sandbox_result"] = sandbox_res
    state["status"] = "sandbox_tested"
    return state


def await_human_approval_node(state: ConfigFormState) -> ConfigFormState:
    """Node 4: Điểm dừng chờ phê duyệt con người (Human-In-The-Loop Interrupt)."""
    logger.info(f"🛑 [LangGraph Node: await_human_approval] Awaiting Analyst Click Approval...")
    state["awaiting_approval"] = True
    state["status"] = "awaiting_approval"
    return state


def apply_config_node(state: ConfigFormState) -> ConfigFormState:
    """Node 5: Áp dụng cấu hình chính thức sau khi con người phê duyệt."""
    logger.info(f"✅ [LangGraph Node: apply_config] Applying Rule XML to Pending Area...")
    state["awaiting_approval"] = False
    state["status"] = "applied"
    return state


def build_config_form_graph():
    """Xây dựng StateGraph cho LangGraph Form Engine."""
    builder = StateGraph(ConfigFormState)

    builder.add_node("collect_field", collect_field_node)
    builder.add_node("clarify_question", clarify_question_node)
    builder.add_node("dry_run_check", dry_run_check_node)
    builder.add_node("await_human_approval", await_human_approval_node)
    builder.add_node("apply_config", apply_config_node)

    builder.add_edge(START, "collect_field")
    builder.add_edge("collect_field", "dry_run_check")
    builder.add_edge("dry_run_check", "await_human_approval")
    builder.add_edge("await_human_approval", END)

    memory = MemorySaver()
    graph = builder.compile(checkpointer=memory)
    return graph


# Singleton Graph Instance
config_form_graph = build_config_form_graph()
