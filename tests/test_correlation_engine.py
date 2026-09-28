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


def detailed_alert(alert_id, timestamp, rule_id, agent_name, source_ip="", destination_ip="", **rule_fields):
    rule = {"id": rule_id, "level": rule_fields.pop("level", 10), "description": rule_fields.pop("description", rule_id)}
    rule.update(rule_fields)
    return {
        "id": alert_id,
        "timestamp": timestamp,
        "rule": rule,
        "agent": {"id": agent_name, "name": agent_name},
        "data": {"srcip": source_ip, "dstip": destination_ip},
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

    def test_deduplication_does_not_merge_same_rule_across_agents(self):
        alerts = [
            detailed_alert("one", "2026-09-15T00:00:00Z", "5710", "web-01"),
            detailed_alert("two", "2026-09-15T00:00:10Z", "5710", "db-01"),
        ]
        deduped = engine.deduplicate_alerts(alerts)
        self.assertEqual(len(deduped), 2)
        self.assertEqual([item["occurrence_count"] for item in deduped], [1, 1])

    def test_deduplication_does_not_merge_distinct_file_events(self):
        first = detailed_alert("one", "2026-09-15T00:00:00Z", "550", "web-01")
        second = detailed_alert("two", "2026-09-15T00:00:10Z", "550", "web-01")
        first["data"]["path"] = "/etc/passwd"
        second["data"]["path"] = "/etc/shadow"
        self.assertEqual(len(engine.deduplicate_alerts([first, second])), 2)

    def test_repeated_burst_is_actionable_but_singleton_is_not(self):
        repeated = engine.deduplicate_alerts([
            detailed_alert("one", "2026-09-15T00:00:00Z", "5710", "web-01"),
            detailed_alert("two", "2026-09-15T00:00:10Z", "5710", "web-01"),
        ])
        repeated_group = engine.correlate_alerts(repeated)[0]
        self.assertTrue(repeated_group["is_correlated"])
        self.assertIn("repeated_activity", repeated_group["correlation_reasons"])
        self.assertEqual(repeated_group["alert_ids"], ["one", "two"])
        self.assertEqual(repeated_group["last_seen"], "2026-09-15T00:00:10+00:00")

        singleton = engine.correlate_alerts([
            detailed_alert("three", "2026-09-15T00:10:00Z", "5501", "db-01")
        ])[0]
        self.assertFalse(singleton["is_correlated"])
        self.assertEqual(singleton["correlation_reason"], "singleton")

    def test_shared_ip_correlates_cross_device_rule_sequence(self):
        groups = engine.correlate_alerts([
            detailed_alert("scan", "2026-09-15T00:00:00Z", "100010", "firewall", "203.0.113.8", "10.0.0.10"),
            detailed_alert("login", "2026-09-15T00:03:00Z", "100015", "web-01", "203.0.113.8", "10.0.0.20"),
        ], time_window_minutes=5)
        self.assertEqual(len(groups), 1)
        self.assertTrue(groups[0]["is_correlated"])
        self.assertIn("shared_ip", groups[0]["correlation_reasons"])
        self.assertIn("rule_sequence", groups[0]["correlation_reasons"])
        self.assertGreaterEqual(groups[0]["correlation_confidence"], 50)

    def test_same_text_without_shared_entity_does_not_correlate(self):
        groups = engine.correlate_alerts([
            detailed_alert("one", "2026-09-15T00:00:00Z", "5710", "web-01", "198.51.100.1"),
            detailed_alert("two", "2026-09-15T00:01:00Z", "5710", "db-01", "198.51.100.2"),
        ])
        self.assertEqual(len(groups), 2)
        self.assertTrue(all(not group["is_correlated"] for group in groups))

    def test_low_level_temporal_noise_on_same_agent_does_not_correlate(self):
        groups = engine.correlate_alerts([
            detailed_alert("one", "2026-09-15T00:00:00Z", "100", "web-01", level=3),
            detailed_alert("two", "2026-09-15T00:01:00Z", "101", "web-01", level=4),
        ])
        self.assertEqual(len(groups), 2)
        self.assertTrue(all(not group["is_correlated"] for group in groups))

    def test_native_mitre_is_exposed_and_scored(self):
        alert_item = detailed_alert(
            "one", "2026-09-15T00:00:00Z", "999001", "web-01",
            mitre={"id": ["T1110"], "tactic": ["Credential Access"]},
        )
        group = engine.correlate_alerts([alert_item])[0]
        self.assertEqual(group["mitre_techniques"], ["T1110"])
        score = engine.score_priority(group, {}, {})
        self.assertEqual(score["breakdown"]["mitre_techniques_found"], ["T1110"])
        self.assertIn("Credential Access", score["breakdown"]["mitre_tactics_found"])

    def test_connected_chain_is_split_at_max_incident_span(self):
        alerts = [
            detailed_alert(f"a-{minute}", f"2026-09-15T00:{minute:02d}:00Z", str(6000 + minute), "web-01")
            for minute in (0, 4, 8, 12)
        ]
        groups = engine.correlate_alerts(alerts, time_window_minutes=5, max_incident_span_minutes=10)
        self.assertEqual(len(groups), 2)
        self.assertTrue(all(group["time_span"]["end"] - group["time_span"]["start"] <= 600 for group in groups))
