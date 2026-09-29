"""Regression tests for stable incident evidence replay."""

import core.server as server


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
