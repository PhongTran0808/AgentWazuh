"""Discord alert notifier for high-severity Wazuh events."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List
from zoneinfo import ZoneInfo

import httpx


logger = logging.getLogger("AgentWazuhDiscord")
MAX_EMBEDS_PER_REQUEST = 10


def _identity(alert: Dict[str, Any]) -> str:
    if alert.get("id") is not None:
        return str(alert["id"])
    raw = json.dumps(alert, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _safe(value: Any, limit: int = 900) -> str:
    text = str(value or "Không có dữ liệu")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _level_color(level: int) -> int:
    if level >= 15:
        return 0x8B0000
    if level >= 13:
        return 0xFF0000
    return 0xFF8C00


def _severity_name(level: int) -> str:
    if level >= 15:
        return "CRITICAL"
    if level >= 12:
        return "HIGH"
    if level >= 7:
        return "MEDIUM"
    return "LOW"


def _discord_safe(value: Any, limit: int = 900) -> str:
    """Keep untrusted Wazuh text inside a Discord-safe code/text field."""
    text = _safe(value, limit)
    red_marker = "\x00RED_CIRCLE\x00"
    text = text.replace("🔴", red_marker)
    text = re.sub(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]", "", text)
    return text.replace(red_marker, "🔴").replace("```", "'''").replace("@everyone", "@ everyone").replace("@here", "@ here")


def _code_block(value: Any, limit: int = 900) -> str:
    return f"```\n{_discord_safe(value, limit)}\n```"


def _display_timestamp(value: Any) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00").replace("+0000", "+00:00"))
        local = parsed.astimezone(ZoneInfo("Asia/Ho_Chi_Minh"))
        return local.strftime("%Y-%m-%d %H:%M:%S (GMT+7)")
    except (TypeError, ValueError):
        return datetime.now(ZoneInfo("Asia/Ho_Chi_Minh")).strftime("%Y-%m-%d %H:%M:%S (GMT+7)")


def _first(data: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _technical_details(alert: Dict[str, Any], rule: Dict[str, Any], agent: Dict[str, Any], data: Dict[str, Any]) -> str:
    values = [
        ("Rule ID", rule.get("id")),
        ("Rule Groups", ", ".join(str(item) for item in (rule.get("groups") or []))),
        ("Agent ID", agent.get("id")),
        ("Source IP", _first(data, "srcip", "src_ip")),
        ("Target IP", _first(data, "dstip", "dst_ip")),
        ("Source Port", _first(data, "srcport", "src_port")),
        ("Target Port", _first(data, "dstport", "dst_port")),
        ("Protocol", _first(data, "proto", "protocol")),
        ("Action", _first(data, "action", "status", "result")),
        ("User", _first(data, "user", "username", "dstuser", "srcuser")),
        ("Process", _first(data, "process", "process_name", "command")),
        ("File / Path", _first(data, "file", "filename", "path", "target")),
        ("Service", _first(data, "service", "app", "application")),
    ]
    lines = [f"{label}: {_discord_safe(value, 240)}" for label, value in values if value not in (None, "", [], {})]
    if not lines:
        lines.append("Structured technical fields: Không có dữ liệu")
    return "\n".join(lines)


def _recommended_action(level: int, source_ip: Any, location: Any) -> str:
    source = _discord_safe(source_ip, 180) if source_ip else "chưa xác định"
    log_source = _discord_safe(location, 240) if location else "chưa xác định"
    return (
        "1. Xác minh alert và đối chiếu với các sự kiện liên quan trong cùng thời gian.\n"
        f"2. Kiểm tra agent/log source: {log_source}.\n"
        f"3. Rà soát source IP {source} trên firewall và danh sách cho phép.\n"
        "4. Nếu xác nhận là sự cố, thực hiện containment theo quy trình SOC và lưu bằng chứng.\n"
        "5. Không tự động chặn hoặc xóa dữ liệu nếu chưa có phê duyệt analyst."
    )


def _discord_timestamp(value: Any) -> str:
    if value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00").replace("+0000", "+00:00"))
            return parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat()


def _alert_embed(alert: Dict[str, Any]) -> Dict[str, Any]:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    level = int(rule.get("level") or 0)
    description = _discord_safe(rule.get("description"), 1000)
    alert_id = _discord_safe(alert.get("id"))
    rule_id = _discord_safe(rule.get("id"))
    agent_name = _discord_safe(agent.get("name"))
    agent_ip = _discord_safe(agent.get("ip"))
    agent_id = _discord_safe(agent.get("id"))
    source_ip = _discord_safe(_first(data, "srcip", "src_ip"))
    destination_ip = _discord_safe(_first(data, "dstip", "dst_ip"))
    location = _discord_safe(alert.get("location"))
    severity = _severity_name(level)
    timestamp = _display_timestamp(alert.get("timestamp"))
    full_log = alert.get("full_log") or "Không có raw log trong alert payload."
    type_model = _first(agent, "os", "platform", "type") or _first(data, "osname", "os", "device_type") or "Wazuh Agent"

    fields = [
        {"name": "Device", "value": _code_block(agent_name, 240), "inline": True},
        {"name": "IP Address", "value": _code_block(agent_ip, 240), "inline": True},
        {"name": "Type / Model", "value": _code_block(type_model, 240), "inline": True},
        {"name": "Location", "value": _code_block(location, 240), "inline": True},
        {"name": "Timestamp", "value": _code_block(timestamp, 240), "inline": True},
        {"name": "Severity", "value": _code_block(f"{severity} (Level {level})", 240), "inline": True},
        {"name": "Technical Details", "value": _code_block(_technical_details(alert, rule, agent, data), 980), "inline": False},
        {"name": "Log Excerpt", "value": _code_block(full_log, 980), "inline": False},
        {"name": "Recommended Action", "value": _code_block(_recommended_action(level, _first(data, "srcip", "src_ip"), alert.get("location")), 980), "inline": False},
    ]
    return {
        "title": f"🔴 [{severity}] {_discord_safe(description, 220)}",
        "description": _code_block(
            f"Wazuh alert {alert_id} from {agent_name}. Rule {rule_id} matched at level {level}.",
            900,
        ),
        "color": _level_color(level),
        "fields": fields,
        "timestamp": _discord_timestamp(alert.get("timestamp")),
        "footer": {"text": f"AgentWazuh | Wazuh REST API | Alert ID: {alert_id} | Agent ID: {agent_id}"},
    }


class DiscordAlertNotifier:
    """Send each qualifying alert once per process to a Discord webhook."""

    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = (webhook_url or os.getenv("DISCORD_WEBHOOK_URL", "")).strip()
        self.sent_ids: set[str] = set()
        self.baseline_initialized = False
        if self.webhook_url:
            self._install_log_redaction()

    def _install_log_redaction(self) -> None:
        webhook_url = self.webhook_url

        class WebhookFilter(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                message = record.getMessage().replace(webhook_url, "<discord-webhook-redacted>")
                record.msg = message
                record.args = ()
                return True

        logging.getLogger("httpx").addFilter(WebhookFilter())

    def prime_baseline(self, alerts: Iterable[Dict[str, Any]]) -> None:
        """Mark startup history as known so restart does not flood Discord."""
        for alert in alerts:
            if int((alert.get("rule") or {}).get("level") or 0) > 11:
                self.sent_ids.add(_identity(alert))
        self.baseline_initialized = True

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    async def notify(self, alerts: Iterable[Dict[str, Any]]) -> int:
        if not self.enabled:
            return 0
        candidates: List[Dict[str, Any]] = []
        for alert in alerts:
            level = int((alert.get("rule") or {}).get("level") or 0)
            identity = _identity(alert)
            if level > 11 and identity not in self.sent_ids:
                candidates.append(alert)
        if not candidates:
            return 0

        delivered = 0
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                for offset in range(0, len(candidates), MAX_EMBEDS_PER_REQUEST):
                    batch = candidates[offset:offset + MAX_EMBEDS_PER_REQUEST]
                    response = await client.post(
                        self.webhook_url,
                        json={
                            "username": "AgentWazuh SOC",
                            "content": f"Wazuh Security Alert | {len(batch)} alert level > 11",
                            "embeds": [_alert_embed(alert) for alert in batch],
                            "allowed_mentions": {"parse": []},
                        },
                    )
                    response.raise_for_status()
                    for alert in batch:
                        self.sent_ids.add(_identity(alert))
                    delivered += len(batch)
            # Keep memory bounded during long-running polling.
            if len(self.sent_ids) > 5000:
                self.sent_ids = set(list(self.sent_ids)[-2500:])
            logger.info("Đã gửi %s alert level > 11 sang Discord.", delivered)
        except Exception as exc:
            # Never expose the secret webhook URL in logs.
            logger.error("Gửi cảnh báo sang Discord thất bại: %s", type(exc).__name__)
        return delivered
