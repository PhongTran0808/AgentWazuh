from typing import Dict, Any, List, Optional, TypedDict


class ConfigFormState(TypedDict, total=False):
    """LangGraph State Schema cho Form Cấu hình Wazuh Rule HITL."""
    session_id: str
    rule_id: Optional[int]
    rule_name: str
    match_pattern: str
    frequency: int
    timeframe: int
    level: int
    parent_rule_id: Optional[int]
    group_name: Optional[str]
    mitre_id: Optional[str]
    query: Optional[str]
    sample_log: Optional[str]
    logtest_report: Optional[Dict[str, Any]]
    rag_evidence: Optional[str]
    local_rule_evidence: Optional[str]
    sandbox_result: Optional[Dict[str, Any]]
    unified_diff: Optional[str]
    reasoning_markdown: Optional[str]
    backup_id: Optional[str]
    approval_id: Optional[str]
    fields_completed: List[str]
    intervening_questions_count: int
    draft_xml: Optional[str]
    sandbox_result: Optional[Dict[str, Any]]
    awaiting_approval: bool
    status: str  # "collecting", "clarifying", "sandbox_tested", "awaiting_approval", "applied", "dismissed"
    sample_alerts: Optional[List[Dict[str, Any]]]
