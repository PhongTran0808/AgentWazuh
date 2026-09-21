"""Small, deterministic Gemini adapter for structured incident analysis.

The correlation engine remains responsible for grouping alerts. Gemini is used
only after grouping, to add semantic classification and an analyst-friendly
explanation. The adapter deliberately returns an explicit unavailable/error
status instead of fabricating an AI result when the key or API is unavailable.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

import requests


class GeminiAnalyzer:
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = Path(base_dir or Path(__file__).resolve().parent.parent)

    def _read_local_env(self) -> Dict[str, str]:
        values: Dict[str, str] = {}
        for filename in ("pass.env", ".env"):
            path = self.base_dir / filename
            if not path.exists():
                continue
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        values[key.strip()] = value.strip().strip("\"'")
            except OSError:
                continue
        return values

    def _config(self) -> Dict[str, Any]:
        path = self.base_dir / "config" / "ai_config.json"
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _api_key(self) -> str:
        local_env = self._read_local_env()
        cfg = self._config()
        return str(
            os.getenv("GEMINI_API_KEY")
            or local_env.get("GEMINI_API_KEY")
            or cfg.get("gemini_api_key")
            or cfg.get("cloud_api_key")
            or ""
        ).strip()

    def _model(self) -> str:
        cfg = self._config()
        return str(cfg.get("gemini_model") or os.getenv("GEMINI_MODEL") or "gemini-2.5-flash").strip()

    @staticmethod
    def _compact_group(group: Dict[str, Any]) -> Dict[str, Any]:
        alerts = []
        for alert in group.get("alerts", [])[:20]:
            rule = alert.get("rule", {}) or {}
            agent = alert.get("agent", {}) or {}
            data = alert.get("data", {}) or {}
            alerts.append({
                "id": alert.get("id"),
                "timestamp": alert.get("timestamp") or alert.get("@timestamp"),
                "rule_id": rule.get("id"),
                "level": rule.get("level", 0),
                "description": rule.get("description", ""),
                "agent": agent.get("name") or agent.get("id"),
                "src_ip": data.get("srcip") or data.get("src_ip"),
                "dst_ip": data.get("dstip") or data.get("dst_ip"),
            })
        return {
            "incident_id": group.get("incident_id") or group.get("group_id"),
            "entity": group.get("entity"),
            "first_seen": group.get("first_seen"),
            "last_seen": group.get("last_seen"),
            "alert_count": group.get("alert_count", len(alerts)),
            "devices": group.get("devices", []),
            "source_ips": group.get("source_ips", []),
            "destination_ips": group.get("destination_ips", []),
            "correlation_reason": group.get("correlation_reason"),
            "python_priority_score": group.get("priority_score", group.get("risk_score")),
            "alerts": alerts,
        }

    @staticmethod
    def parse_json_response(text: str) -> Dict[str, Any]:
        """Parse plain or fenced JSON returned by Gemini."""
        candidate = (text or "").strip()
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", candidate, flags=re.S | re.I)
        if fenced:
            candidate = fenced.group(1)
        else:
            start, end = candidate.find("{"), candidate.rfind("}")
            if start >= 0 and end > start:
                candidate = candidate[start:end + 1]
        value = json.loads(candidate)
        if not isinstance(value, dict):
            raise ValueError("Gemini response is not a JSON object")
        return value

    def analyze_group(self, group: Dict[str, Any]) -> Dict[str, Any]:
        key = self._api_key()
        model = self._model()
        if not key:
            return {
                "status": "unavailable",
                "provider": "gemini",
                "model": model,
                "message": "Chưa cấu hình GEMINI_API_KEY hoặc Gemini API key trong cài đặt AI.",
            }

        compact = self._compact_group(group)
        prompt = (
            "Bạn là SOC Analyst. Phân tích incident group dưới đây bằng tiếng Việt. "
            "Chỉ dùng bằng chứng trong dữ liệu, không bịa IP/thiết bị/sự kiện. "
            "Trả về JSON hợp lệ, không markdown, với các field: "
            "incident_type, priority (LOW/MEDIUM/HIGH/CRITICAL), risk_score (0-100), "
            "mitre_techniques (array), summary, reasoning, confidence (0-1), evidence_ids (array).\n\n"
            f"INCIDENT GROUP:\n{json.dumps(compact, ensure_ascii=False)}"
        )
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        try:
            response = requests.post(
                url,
                params={"key": key},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 900,
                        "responseMimeType": "application/json",
                    },
                },
                timeout=20,
            )
            response.raise_for_status()
            body = response.json()
            text = body["candidates"][0]["content"]["parts"][0]["text"]
            analysis = self.parse_json_response(text)
            return {
                "status": "success",
                "provider": "gemini",
                "model": model,
                "analysis": analysis,
            }
        except (requests.RequestException, KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
            return {
                "status": "error",
                "provider": "gemini",
                "model": model,
                "message": f"Gemini không trả về kết quả hợp lệ: {exc}",
            }


gemini_analyzer = GeminiAnalyzer()

