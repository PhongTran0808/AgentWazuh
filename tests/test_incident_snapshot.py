"""Regression tests for stable incident evidence replay."""

import asyncio

import core.server as server
from services.wazuh_client import WazuhClient


def _group(alert_id: str, rule_id: str, level: int) -> dict:
    return {
        "incident_id": "INC-SNAPSHOT-TEST",
        "group_id": "INC-SNAPSHOT-TEST",
        "entity": "WIN-01",
        "alerts": [{
            "id": alert_id,
            "timestamp": "2026-09-29T02:56:13Z",
            "rule": {"id": rule_id, "level": level, "description": "test"},
            "agent": {"name": "WIN-01"},
            "data": {},
        }],
        "alert_ids": [alert_id],
    }


def test_incident_snapshot_does_not_drift_when_live_group_changes(tmp_path):
    previous_dir = server.INCIDENT_SNAPSHOTS_DIR
    server.INCIDENT_SNAPSHOTS_DIR = tmp_path
    try:
        original = _group("eicar-alert", "100050", 12)
        first = server._get_or_create_incident_snapshot("INC-SNAPSHOT-TEST", original)

        later_live_group = _group("shell-alert", "92052", 4)
        replay = server._get_or_create_incident_snapshot("INC-SNAPSHOT-TEST", later_live_group)

        assert first["alerts"][0]["id"] == "eicar-alert"
        assert replay["alerts"][0]["id"] == "eicar-alert"
        assert replay["alerts"][0]["rule"]["id"] == "100050"
    finally:
        server.INCIDENT_SNAPSHOTS_DIR = previous_dir


def test_incident_id_can_be_recovered_from_manual_query():
    assert server._incident_id_from_query(
        "Phân tích lại nhóm sự cố inc-5ce6a64985d4 sau 1 giờ"
    ) == "INC-5CE6A64985D4"


def test_incident_alert_resolves_from_snapshot_when_missing_from_ui_cache(tmp_path):
    previous_dir = server.INCIDENT_SNAPSHOTS_DIR
    server.INCIDENT_SNAPSHOTS_DIR = tmp_path
    try:
        incident = _group("kKiE8aABWbR5FGPxaNcR", "2501", 5)
        group, scoped, alert, source = server._resolve_investigation_evidence(
            [], incident["alerts"][0]["id"], incident["incident_id"], incident
        )

        assert group["incident_id"] == "INC-SNAPSHOT-TEST"
        assert scoped == incident["alerts"]
        assert alert["id"] == "kKiE8aABWbR5FGPxaNcR"
        assert source == "incident_snapshot"
    finally:
        server.INCIDENT_SNAPSHOTS_DIR = previous_dir


def test_stale_representative_id_falls_back_to_frozen_incident(tmp_path):
    previous_dir = server.INCIDENT_SNAPSHOTS_DIR
    server.INCIDENT_SNAPSHOTS_DIR = tmp_path
    try:
        incident = _group("snapshot-alert", "100050", 12)
        _, _, alert, source = server._resolve_investigation_evidence(
            [], "old-preview-alert", incident["incident_id"], incident
        )

        assert alert["id"] == "snapshot-alert"
        assert source == "incident_snapshot_fallback"
    finally:
        server.INCIDENT_SNAPSHOTS_DIR = previous_dir


def test_missing_standalone_alert_is_not_trusted_from_client_payload():
    group, scoped, alert, source = server._resolve_investigation_evidence(
        [], "forged-or-expired", None, None
    )

    assert group is None
    assert scoped == []
    assert alert is None
    assert source == "unresolved"


def test_direct_alert_lookup_uses_opensearch_document_id(monkeypatch):
    client = WazuhClient(host="127.0.0.1")
    captured = {}

    def fake_fetch(dsl):
        captured.update(dsl)
        return [{"id": "kKiE8aABWbR5FGPxaNcR"}]

    monkeypatch.setattr(client, "_fetch_alerts_opensearch", fake_fetch)

    alert = client.get_alert_by_id("kKiE8aABWbR5FGPxaNcR")

    assert alert["id"] == "kKiE8aABWbR5FGPxaNcR"
    assert captured["query"] == {"ids": {"values": ["kKiE8aABWbR5FGPxaNcR"]}}


def test_incident_raw_alert_ids_include_deduplicated_evidence():
    incident = _group("representative", "2501", 5)
    incident["alert_ids"] = ["representative", "variant-two"]
    incident["alerts"][0]["evidence_ids"] = ["representative", "variant-two", "variant-three"]

    assert server._incident_raw_alert_ids(incident) == [
        "representative", "variant-two", "variant-three"
    ]


def test_batch_alert_lookup_uses_all_exact_document_ids(monkeypatch):
    client = WazuhClient(host="127.0.0.1")
    captured = {}

    def fake_fetch(dsl, timeout=6):
        captured.update(dsl)
        captured["timeout"] = timeout
        return [{"id": "one"}, {"id": "two"}]

    monkeypatch.setattr(client, "_fetch_alerts_opensearch", fake_fetch)

    alerts = client.get_alerts_by_ids(["one", "two", "one"])

    assert [item["id"] for item in alerts] == ["one", "two"]
    assert captured["query"] == {"ids": {"values": ["one", "two"]}}
    assert captured["size"] == 2
    assert captured["timeout"] == 10


def test_incident_analyze_uses_snapshot_without_full_24h_regroup(tmp_path, monkeypatch):
    previous_dir = server.INCIDENT_SNAPSHOTS_DIR
    server.INCIDENT_SNAPSHOTS_DIR = tmp_path
    try:
        incident = _group("scan-1", "2501", 5)
        incident["priority_score"] = 24
        incident["confidence_score"] = 49
        incident["devices"] = ["WEB-01"]
        incident["alert_ids"] = ["scan-1", "scan-2"]
        incident["alerts"][0]["evidence_ids"] = ["scan-1", "scan-2"]
        server._get_or_create_incident_snapshot(incident["incident_id"], incident)

        hydrated = []
        for alert_id, suffix in (("scan-1", "Probing restricted resource: /admin"),
                                 ("scan-2", "Directory enumeration probe detected (10 reqs)")):
            item = _group(alert_id, "2501", 5)["alerts"][0]
            item["full_log"] = f"[WEB_SCAN_DETECTED] User authentication failure from 127.0.0.1 - {suffix}"
            hydrated.append(item)
        monkeypatch.setattr(server.wazuh_client, "get_alerts_by_ids", lambda ids: hydrated)

        async def fail_regroup():
            raise AssertionError("24h regroup must not run when a snapshot exists")

        monkeypatch.setattr(server, "retrieve_correlated_groups", fail_regroup)
        monkeypatch.setattr(server.audit_logger, "log_ai_engine", lambda **kwargs: None)

        result = asyncio.run(server.analyze_correlated_incident(
            server.IncidentAnalyzeRequest(incident_id=incident["incident_id"]), session="test"
        ))

        assert result["ai"]["provider"] == "agentwazuh-deterministic"
        assert "dò quét thư mục" in result["ai"]["analysis"]["summary"]
        assert result["ai"]["analysis"]["mitre_techniques"] == ["T1595"]
        assert "User authentication failure" not in result["incident"]["attack_graph_mermaid"]
    finally:
        server.INCIDENT_SNAPSHOTS_DIR = previous_dir
