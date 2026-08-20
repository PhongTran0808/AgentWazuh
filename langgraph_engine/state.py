from typing import Dict, Any, List, Optional, TypedDict


class ConfigFormState(TypedDict):
    """LangGraph State Schema cho Form Cấu hình Wazuh Rule HITL."""
    session_id: str
    rule_name: str
    match_pattern: str
    frequency: int
    timeframe: int
    level: int
    fields_completed: List[str]
    intervening_questions_count: int
    draft_xml: Optional[str]
    sandbox_result: Optional[Dict[str, Any]]
    awaiting_approval: bool
    status: str  # "collecting", "clarifying", "sandbox_tested", "awaiting_approval", "applied", "dismissed"
