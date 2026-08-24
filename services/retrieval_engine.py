"""
AgentWazuh Retrieval Engine
============================
[CURRENTLY IMPLEMENTED] — Grounded retrieval from Wazuh real data.

Pipeline:
  User Question
       ↓
  RetrievalEngine.retrieve(query, context)
       ↓
  Intent Detection (deterministic keyword matching)
       ↓
  Targeted Data Fetching:
    - Wazuh REST API (agents, manager status)
    - OpenSearch Indexer (alerts)
    - Topology snapshot
    - MITRE mapping lookup
    - Session/conversation history
       ↓
  EvidenceBundle (structured, with metadata)
       ↓
  LLM (reasoning only — NOT inventing data)
       ↓
  Answer

Design principles:
  - LLM does NOT decide what data to fetch.
  - LLM does NOT invent IP addresses, alert counts, or device names.
  - All numerical data comes from this layer (Python deterministic).
  - No vector database — grounded retrieval from Wazuh API and OpenSearch.
"""

import json
import logging
import os
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

logger = logging.getLogger("RetrievalEngine")

# --- Query Intent Categories ---
INTENT_INCIDENT = "incident_analysis"
INTENT_STATUS = "status_check"
INTENT_DEVICE = "device_query"
INTENT_CHART = "chart_visualization"
INTENT_GENERAL = "general"

# Keyword sets for deterministic intent detection
_INCIDENT_KEYWORDS = {
    "tấn công", "brute", "scan", "ransomware", "ddos", "xâm nhập", "alert", "cảnh báo",
    "sự cố", "incident", "rule", "mitre", "cve", "threat", "malware", "phishing",
    "exploit", "payload", "injection", "reverse shell", "privilege", "lateral"
}
_STATUS_KEYWORDS = {
    "trạng thái", "status", "kết nối", "online", "offline", "version", "wazuh server",
    "agent", "connected", "manager", "ping", "heartbeat"
}
_DEVICE_KEYWORDS = {
    "thiết bị", "device", "máy chủ", "server", "host", "ip", "node", "endpoint",
    "fortigate", "firewall", "router", "switch", "dmz", "danh sách"
}
_CHART_KEYWORDS = {
    "biểu đồ", "chart", "thống kê", "phân tích", "báo cáo", "report", "distribution",
    "theo giờ", "hourly", "severity", "top rules", "pie", "bar", "line"
}


@dataclass
class AlertEvidence:
    """Structured evidence from a single alert."""
    alert_id: str
    source: str  # "wazuh_cache" | "opensearch" | "imported"
    agent_id: str
    agent_name: str
    agent_ip: str
    timestamp: str
    rule_id: str
    rule_level: int
    rule_description: str
    source_ip: str
    destination_ip: str
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceBundle:
    """
    Structured evidence package passed to LLM.
    LLM reasons on this — does NOT invent additional data.
    """
    query_intent: str
    retrieval_timestamp: str
    wazuh_host: str

    # Core evidence
    alerts: List[AlertEvidence] = field(default_factory=list)
    agents: List[Dict[str, Any]] = field(default_factory=list)
    system_status: Dict[str, Any] = field(default_factory=dict)
    alert_stats: Dict[str, Any] = field(default_factory=dict)
    topology_nodes: List[Dict[str, Any]] = field(default_factory=list)
    mitre_lookups: List[Dict[str, Any]] = field(default_factory=list)

    # Derived metrics (Python-computed, NOT by LLM)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    top_rules: List[Dict[str, Any]] = field(default_factory=list)
    hourly_distribution: Dict[str, Any] = field(default_factory=dict)

    # Grounding metadata
    alert_count_retrieved: int = 0
    data_sources_used: List[str] = field(default_factory=list)
    retrieval_errors: List[str] = field(default_factory=list)

    def to_context_string(self) -> str:
        """Serialize evidence to structured context string for LLM prompt."""
        lines = [
            f"[RETRIEVAL ENGINE] Query Intent: {self.query_intent}",
            f"[RETRIEVAL ENGINE] Wazuh Host: {self.wazuh_host}",
            f"[RETRIEVAL ENGINE] Retrieved at: {self.retrieval_timestamp}",
            f"[RETRIEVAL ENGINE] Data Sources: {', '.join(self.data_sources_used)}",
            f"[RETRIEVAL ENGINE] Alerts Retrieved: {self.alert_count_retrieved}",
        ]

        if self.retrieval_errors:
            lines.append(f"[RETRIEVAL ERRORS] {'; '.join(self.retrieval_errors)}")

        if self.system_status:
            lines.append(f"\n[SYSTEM STATUS]\n{json.dumps(self.system_status, ensure_ascii=False)}")

        if self.alert_stats:
            lines.append(f"\n[ALERT STATISTICS — OPENSEARCH AGGREGATION]\n{json.dumps(self.alert_stats, ensure_ascii=False)}")

        if self.severity_distribution:
            lines.append(f"\n[SEVERITY DISTRIBUTION — PYTHON COMPUTED]\n{json.dumps(self.severity_distribution, ensure_ascii=False)}")

        if self.top_rules:
            lines.append(f"\n[TOP RULES — PYTHON COMPUTED]\n{json.dumps(self.top_rules, ensure_ascii=False)}")

        if self.hourly_distribution:
            lines.append(f"\n[HOURLY DISTRIBUTION (UTC+7) — PYTHON COMPUTED]\n{json.dumps(self.hourly_distribution, ensure_ascii=False)}")

        if self.agents:
            lines.append(f"\n[REGISTERED WAZUH AGENTS]\n{json.dumps(self.agents[:20], ensure_ascii=False)}")

        if self.mitre_lookups:
            lines.append(f"\n[MITRE ATT&CK LOOKUPS — STATIC MAPPING]\n{json.dumps(self.mitre_lookups, ensure_ascii=False)}")

        if self.alerts:
            alert_dicts = []
            for a in self.alerts[:15]:  # Cap at 15 to avoid prompt bloat
                alert_dicts.append({
                    "alert_id": a.alert_id,
                    "source": a.source,
                    "agent_id": a.agent_id,
                    "agent_name": a.agent_name,
                    "agent_ip": a.agent_ip,
                    "timestamp": a.timestamp,
                    "rule_id": a.rule_id,
                    "rule_level": a.rule_level,
                    "rule_description": a.rule_description,
                    "source_ip": a.source_ip,
                    "destination_ip": a.destination_ip,
                })
            lines.append(f"\n[ALERT EVIDENCE — {len(self.alerts)} ALERTS (showing top {len(alert_dicts)})]")
            lines.append(json.dumps(alert_dicts, ensure_ascii=False))

        return "\n".join(lines)


class RetrievalEngine:
    """
    Grounded retrieval engine for AgentWazuh.
    Fetches real data from Wazuh/OpenSearch and packages into structured EvidenceBundle.
    LLM receives EvidenceBundle — does NOT access raw APIs directly.

    [CURRENTLY IMPLEMENTED]: All retrieval is deterministic Python logic.
    [NOT IMPLEMENTED]: Vector similarity search (not needed for current use case).
    """

    def __init__(self, wazuh_client=None, mitre_mappings: Dict[str, Any] = None):
        self._wazuh_client = wazuh_client
        self._mitre_mappings = mitre_mappings or {}

    def detect_intent(self, query: str) -> str:
        """Deterministic intent detection via keyword matching. No LLM involved."""
        q = query.lower().strip()
        if any(k in q for k in _INCIDENT_KEYWORDS):
            return INTENT_INCIDENT
        if any(k in q for k in _CHART_KEYWORDS):
            return INTENT_CHART
        if any(k in q for k in _STATUS_KEYWORDS):
            return INTENT_STATUS
        if any(k in q for k in _DEVICE_KEYWORDS):
            return INTENT_DEVICE
        return INTENT_GENERAL

    def _extract_alert_evidence(self, raw_alert: Dict[str, Any], source: str = "cache") -> AlertEvidence:
        """Convert raw alert dict to structured AlertEvidence with metadata."""
        data = raw_alert.get("data", {})
        rule = raw_alert.get("rule", {})
        agent = raw_alert.get("agent", {})
        return AlertEvidence(
            alert_id=str(raw_alert.get("id", "")),
            source=source,
            agent_id=str(agent.get("id", "")),
            agent_name=agent.get("name", ""),
            agent_ip=agent.get("ip", ""),
            timestamp=raw_alert.get("timestamp", ""),
            rule_id=str(rule.get("id", "")),
            rule_level=int(rule.get("level", 0)),
            rule_description=rule.get("description", ""),
            source_ip=data.get("srcip", ""),
            destination_ip=data.get("dstip", ""),
            raw_data=data,
        )

    def retrieve(
        self,
        query: str,
        system_context: Optional[Dict[str, Any]] = None,
        alert_data: Optional[Dict[str, Any]] = None,
        recent_alerts: Optional[List[Dict[str, Any]]] = None,
        topology_snapshot: Optional[List[Dict[str, Any]]] = None,
    ) -> EvidenceBundle:
        """
        Main retrieval method. Fetches evidence based on query intent.
        Returns a structured EvidenceBundle — NOT raw JSON strings.

        Parameters:
          query:            The user's question
          system_context:   Dict with wazuh status, agents, alert_stats, etc.
          alert_data:       Single alert if this is an alert-specific investigation
          recent_alerts:    List of recent alerts from cache (for context)
          topology_snapshot: Network topology nodes from 9090 API

        Returns:
          EvidenceBundle with all retrieved evidence and computed metrics
        """
        intent = self.detect_intent(query)
        wazuh_host = (system_context or {}).get("wazuh_host", os.getenv("WAZUH_HOST", ""))
        now_iso = datetime.now(tz=timezone.utc).isoformat()

        bundle = EvidenceBundle(
            query_intent=intent,
            retrieval_timestamp=now_iso,
            wazuh_host=wazuh_host,
        )

        # --- 1. System Status & Agent List ---
        if system_context:
            bundle.system_status = {
                "status": system_context.get("status", "unknown"),
                "version": system_context.get("version", ""),
                "wazuh_host": wazuh_host,
                "total_agents": system_context.get("total_agents", 0),
                "active_agents": system_context.get("active_agents", 0),
                "disconnected_agents": system_context.get("disconnected_agents", 0),
                "error": system_context.get("error"),
            }
            bundle.agents = system_context.get("agents", [])
            bundle.alert_stats = system_context.get("alert_stats", {})
            bundle.data_sources_used.append("wazuh_system_context")

        # --- 2. Alert Evidence ---
        alert_list = []
        source_tag = "cache"

        if alert_data:
            # Single alert investigation
            alert_list = [alert_data]
            source_tag = "selected_alert"
        elif recent_alerts:
            alert_list = recent_alerts
            source_tag = "wazuh_cache"

        for raw in alert_list:
            bundle.alerts.append(self._extract_alert_evidence(raw, source=source_tag))

        bundle.alert_count_retrieved = len(bundle.alerts)
        if alert_list:
            bundle.data_sources_used.append(f"alerts({source_tag})")

        # --- 3. MITRE Lookup for focused alert ---
        if alert_data and self._mitre_mappings:
            rule_id = str(alert_data.get("rule", {}).get("id", ""))
            mapping = self._mitre_mappings.get(rule_id)
            if mapping:
                bundle.mitre_lookups.append(mapping)
                bundle.data_sources_used.append("mitre_static_mapping")

        # --- 4. Topology Nodes (only layout/position from 9090) ---
        if topology_snapshot:
            bundle.topology_nodes = topology_snapshot
            bundle.data_sources_used.append("topology_9090")

        # --- 5. Compute Derived Metrics (Python deterministic — NOT LLM) ---
        # Use aggregation stats from system_context if available (most accurate)
        agg = bundle.alert_stats
        if agg and agg.get("total_24h", 0) > 0:
            bundle.severity_distribution = {
                "critical": agg.get("critical", 0),
                "high": agg.get("high", 0),
                "medium": agg.get("medium", 0),
                "low": agg.get("low", 0),
                "total": agg.get("total_24h", 0),
                "source": "opensearch_aggregation"
            }
            if "hourly_local" in agg:
                bundle.hourly_distribution = {
                    "labels": list(agg["hourly_local"].keys()),
                    "data": list(agg["hourly_local"].values()),
                    "non_zero_hours": agg.get("non_zero_hours", {}),
                    "timezone": "UTC+7 (Giờ Việt Nam)",
                    "source": "opensearch_aggregation"
                }
        elif bundle.alerts:
            # Fallback: compute from alert list
            severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(bundle.alerts)}
            rule_counts: Dict[str, int] = {}
            for a in bundle.alerts:
                lvl = a.rule_level
                if lvl >= 15:
                    severity["critical"] += 1
                elif lvl >= 12:
                    severity["high"] += 1
                elif lvl >= 7:
                    severity["medium"] += 1
                else:
                    severity["low"] += 1
                rule_counts[a.rule_id] = rule_counts.get(a.rule_id, 0) + 1
            severity["source"] = "alert_cache_computed"
            bundle.severity_distribution = severity
            bundle.top_rules = [
                {"rule_id": k, "count": v} for k, v in
                sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            ]

        return bundle
