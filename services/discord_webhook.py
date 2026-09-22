"""Discord alert notifier for high-severity Wazuh events."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

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
    description = _safe(rule.get("description"), 1000)
    alert_id = _safe(alert.get("id"))
    rule_id = _safe(rule.get("id"))
    agent_name = _safe(agent.get("name"))
    agent_ip = _safe(agent.get("ip"))
    source_ip = _safe(data.get("srcip") or data.get("src_ip"))
    destination_ip = _safe(data.get("dstip") or data.get("dst_ip"))

    fields = [
        {"name": "🎯 Rule", "value": f"`{rule_id}` — {_safe(description, 700)}", "inline": False},
        {"name": "🖥️ Agent", "value": f"`{agent_name}`\nIP: `{agent_ip}`", "inline": True},
        {"name": "🌐 Network", "value": f"Source: `{source_ip}`\nDest: `{destination_ip}`", "inline": True},
        {"name": "🆔 Alert ID", "value": f"`{alert_id}`", "inline": True},
    ]
    return {
        "title": f"🚨 Wazuh Alert — Level {level}",
        "description": "**Cảnh báo mức cao cần analyst kiểm tra.**",
        "color": _level_color(level),
        "fields": fields,
        "timestamp": _discord_timestamp(alert.get("timestamp")),
        "footer": {"text": "AgentWazuh SOC • Wazuh REST API"},
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
                            "avatar_url": "https://cdn-icons-png.flaticon.com/512/3067/3067256.png",
                            "content": f"🚨 **{len(batch)} cảnh báo Wazuh level > 11**",
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
