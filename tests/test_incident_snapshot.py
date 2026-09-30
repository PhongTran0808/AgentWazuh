"""Regression tests for stable incident evidence replay."""

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
