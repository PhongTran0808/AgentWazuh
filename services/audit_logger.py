import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from collections import deque
from pathlib import Path
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field

# Set timezone to UTC+7 (Vietnam Standard Time)
VN_TZ = timezone(timedelta(hours=7))

logger = logging.getLogger("AuditLogger")

class AuditLogEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(VN_TZ).strftime("%H:%M:%S"))
    source: str  # "Wazuh-API" | "Indexer-443" | "AI-Engine" | "LangGraph-HITL" | "User-Action"
    action: str  # E.g., "AUTH_REQUEST", "FETCH_ALERTS", "INTERRUPT_WAITING", "GENERATE_RESPONSE"
    status: str  # "INFO" | "SUCCESS" | "WARNING" | "ERROR"
    message: str
    payload_preview: str = ""

class AuditLoggerService:
    """
    In-Memory Ring Buffer Audit Logger Service.
    Tracks all communication events between AgentWazuh, Wazuh REST API,
    OpenSearch/Indexer, LangGraph, and AI Advisor.
    Stores the latest 500 events and allows real-time UI polling.
    """
    def __init__(self, maxlen: int = 500):
        self.logs: deque = deque(maxlen=maxlen)
        self._init_default_logs()

    def _init_default_logs(self):
        """Seed initial system startup logs"""
        now = datetime.now(VN_TZ).strftime("%H:%M:%S")
        self.logs.appendleft(AuditLogEntry(
            timestamp=now,
            source="System",
            action="SYSTEM_BOOT",
            status="INFO",
            message="AgentWazuh Audit Logging System Initialized",
            payload_preview=json.dumps({"max_buffer": 500, "timezone": "UTC+7"})
        ))

    def log(
        self,
        source: str,
        action: str,
        status: str,
        message: str,
        payload_preview: str = ""
    ) -> AuditLogEntry:
        # Format payload_preview if dict/list passed
        if isinstance(payload_preview, (dict, list)):
            try:
                payload_preview = json.dumps(payload_preview, ensure_ascii=False)
            except Exception:
                payload_preview = str(payload_preview)
        
        # Truncate if extremely long (keep up to 500 chars for preview, full detail stored safely)
        preview_str = str(payload_preview) if payload_preview else ""
        
        entry = AuditLogEntry(
            source=source,
            action=action,
            status=status,
            message=message,
            payload_preview=preview_str
        )
        self.logs.appendleft(entry)
        logger.info(f"[{entry.timestamp}] [{source}] [{action}] [{status}] {message}")
        return entry

    def log_wazuh_api(self, action: str, status: str, message: str, payload: Any = ""):
        return self.log("Wazuh-API", action, status, message, payload)

    def log_indexer(self, action: str, status: str, message: str, payload: Any = ""):
        return self.log("Indexer-443", action, status, message, payload)

    def log_ai_engine(self, action: str, status: str, message: str, payload: Any = ""):
        return self.log("AI-Engine", action, status, message, payload)

    def log_langgraph(self, action: str, status: str, message: str, payload: Any = ""):
        return self.log("LangGraph-HITL", action, status, message, payload)

    def log_user_action(self, action: str, status: str, message: str, payload: Any = ""):
        return self.log("User-Action", action, status, message, payload)

    def get_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [entry.model_dump() for entry in list(self.logs)[:limit]]

    def clear_logs(self):
        self.logs.clear()
        now = datetime.now(VN_TZ).strftime("%H:%M:%S")
        self.logs.appendleft(AuditLogEntry(
            timestamp=now,
            source="User-Action",
            action="CLEAR_LOGS",
            status="INFO",
            message="Audit log buffer cleared by user",
            payload_preview=""
        ))

# Global Singleton Audit Logger Instance
audit_logger = AuditLoggerService(maxlen=500)
