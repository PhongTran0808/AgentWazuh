import json
from typing import Dict, Any, Optional
from services.case_manager import CaseManager

case_mgr = CaseManager()


def create_incident_case_tool(
    title: str,
    severity: str = "HIGH",
    risk_score: int = 85,
    mitre_technique: str = "T1110.001 (Brute Force)",
    description: str = "Phát hiện bão log đăng nhập bất thường",
    webhook_url: Optional[str] = None
) -> str:
    """
    AI Agent Tool: Tự động tạo Hồ sơ Sự cố (Case Ticket) và gửi qua Webhook/TheHive.
    """
    payload = case_mgr.generate_case_payload(
        title=title,
        severity=severity,
        risk_score=risk_score,
        mitre_technique=mitre_technique,
        description=description
    )
    result = case_mgr.send_webhook_case(payload, target_url=webhook_url)
    return json.dumps({"case_payload": payload, "dispatch_result": result}, indent=2, ensure_ascii=False)
