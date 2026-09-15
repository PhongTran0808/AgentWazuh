import unittest

import services.correlation_engine as engine


def alert(alert_id, timestamp, source_ip):
    return {
        "id": alert_id,
        "timestamp": timestamp,
        "rule": {"id": "5710", "level": 10, "description": "SSH authentication failed"},
        "agent": {"name": "web-01"},
        "data": {"srcip": source_ip},
    }


class CorrelationFallbackTests(unittest.TestCase):
    def test_fallback_groups_same_entity_and_preserves_audit_fields(self):
        original_nx = engine.nx
        engine.nx = None
        try:
            groups = engine.correlate_alerts([
                alert("one", "2026-09-15T00:00:00Z", "10.0.0.5"),
                alert("two", "2026-09-15T00:02:00Z", "10.0.0.5"),
                alert("three", "2026-09-15T00:02:00Z", "10.0.0.6"),
            ], time_window_minutes=5)
        finally:
            engine.nx = original_nx

        self.assertEqual(len(groups), 2)
        grouped = next(group for group in groups if group["entity"] == "10.0.0.5")
        self.assertEqual(grouped["alert_count"], 2)
        self.assertEqual(grouped["correlation_reason"], "shared_entity_temporal_fallback")
        self.assertTrue(grouped["incident_id"].startswith("INC-"))

    def test_empty_alerts_returns_empty_group_list(self):
        self.assertEqual(engine.correlate_alerts([]), [])
