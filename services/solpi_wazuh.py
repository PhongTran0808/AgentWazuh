"""SoL-Pi-inspired evidence packing for Wazuh investigations.

The upstream SoL-Pi project is a Pi/TypeScript extension.  This module keeps
the same safety properties at the AgentWazuh boundary without requiring a Pi
runtime: large observations are archived locally behind stable handles, prompt
receipts only quote fields extracted from that archive, and prior investigation
state is kept as bounded, compact metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


HANDLE_PREFIX = "wazuh-observation:sha256:"
HANDLE_RE = re.compile(r"^wazuh-observation:sha256:([a-f0-9]{64})$")
MAX_RECEIPT_ALERTS = 12
MAX_CONTEXT_ENTRIES = 6


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _safe_text(value: Any, limit: int = 280) -> str:
    text = str(value or "")
    return text if len(text) <= limit else f"{text[:limit - 1]}…"


@dataclass(frozen=True)
class ObservationReceipt:
    handle: str
    sha256: str
    source_bytes: int
    source_alert_count: int
    evidence: List[Dict[str, Any]]
    prior_context: List[Dict[str, Any]]

    def to_prompt_context(self) -> str:
        """Render a small, deterministic receipt.  Raw logs stay on disk."""
        lines = [
            "[SOL-PI WAZUH EVIDENCE RECEIPT]",
            f"- Observation handle: {self.handle}",
            f"- Source SHA-256: {self.sha256}",
            f"- Archived source bytes: {self.source_bytes}",
            f"- Alerts archived: {self.source_alert_count}; evidence quoted: {len(self.evidence)}",
            "- Every quoted value below is copied from the archived observation. Do not invent values not present here.",
        ]
        if self.prior_context:
            lines.append("- Compact prior investigation state (metadata only):")
            for item in self.prior_context:
                lines.append(
                    f"  + {item.get('timestamp', '')}: {item.get('query', '')} "
                    f"(handle {item.get('handle', '')}, alerts {item.get('alert_count', 0)})"
                )
        if self.evidence:
            lines.append("- Evidence receipts:")
            for item in self.evidence:
                lines.append(f"  + {json.dumps(item, ensure_ascii=False, separators=(',', ':'))}")
        return "\n".join(lines)


class WazuhSoLPi:
    """Local ObservationPack, evidence receipt, action fusion, and compact context."""

    def __init__(self, base_dir: Path):
        self.root = Path(os.getenv("SOLPI_WAZUH_DATA_DIR", str(base_dir / "data" / "solpi_wazuh")))
        self.blob_dir = self.root / "observations"
        self.context_dir = self.root / "contexts"
        self.ledger_path = self.root / "ledger.jsonl"
        self.root.mkdir(parents=True, exist_ok=True)
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        self.context_dir.mkdir(parents=True, exist_ok=True)

    def _append_ledger(self, event: str, **details: Any) -> None:
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **details}
        with self.ledger_path.open("a", encoding="utf-8") as ledger:
            ledger.write(_canonical_json(entry) + "\n")
        try:
            os.chmod(self.ledger_path, 0o600)
        except OSError:
            pass

    def archive(self, payload: Any) -> tuple[str, str, int]:
        """Persist an exact canonical observation once and return a stable handle."""
        body = _canonical_json(payload)
        encoded = body.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        path = self.blob_dir / f"{digest}.json"
        if not path.exists():
            path.write_bytes(encoded)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        return f"{HANDLE_PREFIX}{digest}", digest, len(encoded)

    @staticmethod
    def _evidence_from_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
        rule = alert.get("rule") or {}
        agent = alert.get("agent") or {}
        data = alert.get("data") or {}
        # These values are intentionally taken directly from the raw observation.
        return {
            "alert_id": _safe_text(alert.get("id")),
            "timestamp": _safe_text(alert.get("timestamp")),
            "rule_id": _safe_text(rule.get("id")),
            "rule_level": rule.get("level"),
            "rule_description": _safe_text(rule.get("description")),
            "agent": _safe_text(agent.get("name")),
            "source_ip": _safe_text(data.get("srcip") or data.get("src_ip") or alert.get("srcip")),
            "destination_ip": _safe_text(data.get("dstip") or data.get("dst_ip") or alert.get("dstip")),
        }

    def _context_path(self, session_id: str) -> Path:
        token = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        return self.context_dir / f"{token}.json"

    def _load_context(self, session_id: str) -> List[Dict[str, Any]]:
        path = self._context_path(session_id)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def _save_context(self, session_id: str, entries: List[Dict[str, Any]]) -> None:
        path = self._context_path(session_id)
        path.write_text(_canonical_json(entries[-MAX_CONTEXT_ENTRIES:]), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def build_investigation_package(
        self,
        session_id: str,
        query: str,
        alert_data: Optional[Dict[str, Any]],
        recent_alerts: Optional[List[Dict[str, Any]]],
        system_status: Optional[Dict[str, Any]],
    ) -> ObservationReceipt:
        """Action Fusion: archive, reduce, and compact context in one local operation."""
        alerts = [alert_data] if alert_data else list(recent_alerts or [])
        source = {
            "schema": "agentwazuh.solpi.observation.v1",
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "query": query,
            "system_status": system_status or {},
            "alerts": alerts,
        }
        handle, digest, source_bytes = self.archive(source)
        prior_context = self._load_context(session_id)
        evidence = [self._evidence_from_alert(alert) for alert in alerts[:MAX_RECEIPT_ALERTS]]
        compact_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "query": _safe_text(query, 180),
            "handle": handle,
            "alert_count": len(alerts),
        }
        self._save_context(session_id, prior_context + [compact_entry])
        self._append_ledger(
            "action_fusion_applied",
            handle=handle,
            source_sha256=digest,
            source_bytes=source_bytes,
            source_alert_count=len(alerts),
            evidence_count=len(evidence),
        )
        return ObservationReceipt(handle, digest, source_bytes, len(alerts), evidence, prior_context[-3:])

    def read_observation(self, handle: str, offset: int = 0, limit: int = 16_384) -> Dict[str, Any]:
        """Exact, paged recall of a local ObservationPack archive."""
        match = HANDLE_RE.fullmatch(handle)
        if not match:
            raise ValueError("Invalid observation handle")
        offset = max(0, offset)
        limit = min(max(1, limit), 65_536)
        path = self.blob_dir / f"{match.group(1)}.json"
        if not path.exists():
            raise FileNotFoundError("Observation archive not found")
        body = path.read_text(encoding="utf-8")
        page = body[offset:offset + limit]
        self._append_ledger("observation_recalled", handle=handle, offset=offset, returned_chars=len(page))
        return {
            "handle": handle,
            "sha256": match.group(1),
            "offset": offset,
            "limit": limit,
            "total_chars": len(body),
            "next_offset": offset + len(page) if offset + len(page) < len(body) else None,
            "content": page,
        }
