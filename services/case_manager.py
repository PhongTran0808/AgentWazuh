import json
import logging
import requests
from typing import Dict, Any, List, Optional

from datetime import datetime, timezone

logger = logging.getLogger("CaseManager")


class CaseManager:
    """
    Phân hệ Quản lý Hồ sơ Sự cố (Incident Case Management Integration):
    - Tự động đóng gói Báo cáo sự cố (Risk Score, MITRE TTPs, Bằng chứng log).
    - Hỗ trợ gửi sang TheHive v5 API, Jira Service Management REST API, hoặc Generic Webhook Receiver.
    """

    def __init__(self, webhook_url: Optional[str] = None, thehive_url: Optional[str] = None, api_key: Optional[str] = None):
        self.webhook_url = webhook_url
        self.thehive_url = thehive_url
        self.api_key = api_key

    def generate_case_payload(
        self,
        title: str,
        severity: str,
        risk_score: int,
        mitre_technique: str,
        description: str,
        alert_details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Tạo chuẩn hóa JSON Payload chứa Hồ sơ Sự cố SOC."""
        return {
            "title": f"🚨 [SOC CASE] {title}",
            "severity": severity.upper(),
            "risk_score": risk_score,
            "mitre_technique": mitre_technique,
            "description": description,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "AWAITING_HUMAN_APPROVAL",
            "alert_evidence": alert_details or {},
            "playbook_recommendations": [
                "1. Cách ly địa chỉ IP nguồn trên Tường lửa FortiGate.",
                "2. Kiểm tra log đăng nhập trên hệ thống DMZ Server.",
                "3. Kích hoạt Form Cấu hình Rule lọc tần suất nháp trên LangGraph Engine."
            ]
        }

    def send_webhook_case(self, payload: Dict[str, Any], target_url: Optional[str] = None) -> Dict[str, Any]:
        """Gửi Hồ sơ Sự cố sang Webhook Receiver (Jira/Trello/Discord/Slack/SOC Custom Receiver)."""
        url = target_url or self.webhook_url or "https://httpbin.org/post"
        try:
            res = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=5.0)
            logger.info(f"✅ [CaseManager] Webhook dispatched to '{url}' | HTTP {res.status_code}")
            return {
                "status": "success",
                "http_code": res.status_code,
                "target_url": url,
                "response": res.text[:200]
            }
        except Exception as e:
            logger.error(f"❌ [CaseManager] Webhook dispatch failed: {e}")
            return {"status": "error", "message": str(e)}

    def create_thehive_case(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Tạo Case trực tiếp trên TheHive v5 REST API (/api/v1/case)."""
        if not self.thehive_url:
            # Simulated local mock response if no live TheHive instance configured
            return {
                "status": "success_mock",
                "case_id": "THEHIVE-CASE-2026-0820",
                "message": "🟢 Hồ sơ Sự cố đã được đóng gói và lưu vết vào hệ thống Case Management."
            }

        url = f"{self.thehive_url.rstrip('/')}/api/v1/case"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        thehive_payload = {
            "title": payload["title"],
            "description": payload["description"],
            "severity": 3 if payload["severity"] == "HIGH" else 2,
            "tags": ["AgentWazuh", "SOC_CoPilot", payload["mitre_technique"]],
            "flag": True
        }
        try:
            res = requests.post(url, json=thehive_payload, headers=headers, verify=False, timeout=5.0)
            return {"status": "success", "http_code": res.status_code, "data": res.json()}
        except Exception as e:
            return {"status": "error", "message": str(e)}
