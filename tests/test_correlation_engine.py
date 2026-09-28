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


class MultiEntityAndGraphUpgradeTests(unittest.TestCase):
    def test_extract_alert_entities(self):
        sample = {
            "id": "alert-101",
            "timestamp": "2026-09-28T08:00:00Z",
            "rule": {"id": "100104", "level": 12, "description": "Privilege escalation detected"},
            "agent": {"id": "002", "name": "ubuntu-dmz"},
            "data": {
                "srcip": "192.168.1.50",
                "dstip": "10.0.0.10",
                "srcuser": "www-data",
                "dstuser": "root",
                "devname": "FGT-Branch-01"
            }
        }
        entities = engine.extract_alert_entities(sample)
        self.assertIn("192.168.1.50", entities["src_ips"])
        self.assertIn("10.0.0.10", entities["dst_ips"])
        self.assertIn("ubuntu-dmz", entities["agents"])
        self.assertIn("root", entities["users"])
        self.assertIn("FGT-Branch-01", entities["devnames"])
        self.assertEqual(entities["rule_id"], "100104")
        self.assertEqual(entities["rule_level"], 12)

    def test_weighted_graph_correlation_links_multi_stage_attack(self):
        # Alert 1: External brute force from 192.168.1.100 to 10.0.0.50
        a1 = {
            "id": "stage-1",
            "timestamp": "2026-09-28T09:00:00Z",
            "rule": {"id": "5710", "level": 10, "description": "SSH Authentication failed"},
            "agent": {"name": "dmz-server"},
            "data": {"srcip": "192.168.1.100", "dstip": "10.0.0.50", "dstuser": "admin"}
        }
        # Alert 2: Lateral movement - dmz-server (10.0.0.50) connects to internal db (10.0.0.99)
        a2 = {
            "id": "stage-2",
            "timestamp": "2026-09-28T09:02:00Z",
            "rule": {"id": "100104", "level": 12, "description": "Lateral movement connection via SSH"},
            "agent": {"name": "dmz-server"},
            "data": {"srcip": "10.0.0.50", "dstip": "10.0.0.99", "dstuser": "root"}
        }

        groups = engine.correlate_alerts([a1, a2], time_window_minutes=15)
        self.assertEqual(len(groups), 1, "Multi-stage lateral attack should be correlated into 1 group")
        group = groups[0]
        self.assertEqual(group["involved_alerts"], 2)
        self.assertIn("confidence_score", group)
        self.assertGreaterEqual(group["confidence_score"], 40)
        self.assertLessEqual(group["confidence_score"], 98)
        self.assertIn("attack_graph_mermaid", group)
        self.assertIn("graph LR", group["attack_graph_mermaid"])

    def test_generate_incident_attack_graph_mermaid_structure(self):
        group = {
            "incident_id": "INC-TEST123",
            "entity": "192.168.1.100",
            "source_ips": ["192.168.1.100"],
            "destination_ips": ["10.0.0.50"],
            "devices": ["dmz-server"],
            "alerts": [
                {
                    "id": "a1",
                    "timestamp": "2026-09-28T09:00:00Z",
                    "rule": {"id": "5710", "level": 10, "description": "SSH Brute Force"}
                },
                {
                    "id": "a2",
                    "timestamp": "2026-09-28T09:03:00Z",
                    "rule": {"id": "100104", "level": 12, "description": "Privilege Escalation root"}
                }
            ]
        }
        mermaid = engine.generate_incident_attack_graph_mermaid(group)
        self.assertTrue(mermaid.startswith("graph LR"))
        self.assertIn("classDef attacker", mermaid)
        self.assertIn("classDef target", mermaid)
        self.assertIn("Nguồn:", mermaid)
        self.assertIn("Mục Tiêu:", mermaid)
        self.assertIn("Bước 1: Rule 5710", mermaid)
        self.assertIn("Bước 2: Rule 100104", mermaid)


class WazuhFactualQueryTests(unittest.TestCase):
    def setUp(self):
        from services.incident_assistant import IncidentAssistant
        self.assistant = IncidentAssistant()
        self.mock_context = {
            "status": "online",
            "version": "Wazuh v4.14.7",
            "wazuh_host": "172.16.175.145",
            "agents": [
                {
                    "id": "001",
                    "name": "ubuntu-dmz",
                    "ip": "10.0.0.50",
                    "status": "active",
                    "os": {"name": "Ubuntu", "version": "22.04"},
                    "lastKeepAlive": "2026-09-28T09:00:00Z"
                },
                {
                    "id": "002",
                    "name": "windows-ad",
                    "ip": "10.0.0.60",
                    "status": "disconnected",
                    "os": {"name": "Windows Server", "version": "2022"},
                    "lastKeepAlive": "2026-09-27T10:00:00Z"
                }
            ],
            "total_agents": 2,
            "active_agents": 1,
            "disconnected_agents": 1,
            "alert_stats": {
                "total_24h": 150,
                "critical": 5,
                "high": 15,
                "medium": 30,
                "low": 100
            },
            "error": None
        }

    def test_query_agent_count_and_list(self):
        res = self.assistant.resolve_wazuh_server_factual_query(
            "Wazuh server có bao nhiêu agent?",
            self.mock_context
        )
        self.assertIsNotNone(res)
        self.assertIn("172.16.175.145", res)
        self.assertIn("2", res)
        self.assertIn("ubuntu-dmz", res)
        self.assertIn("windows-ad", res)
        self.assertIn("🟢 ACTIVE", res)
        self.assertIn("🔴 DISCONNECTED", res)
        self.assertNotIn("/ /", res)

    def test_query_server_version_and_status(self):
        res = self.assistant.resolve_wazuh_server_factual_query(
            "Wazuh server đang chạy phiên bản bao nhiêu?",
            self.mock_context
        )
        self.assertIsNotNone(res)
        self.assertIn("Wazuh v4.14.7", res)
        self.assertIn("ONLINE", res)
        self.assertIn("55000", res)
        self.assertNotIn("/ /", res)

    def test_query_alert_stats(self):
        res = self.assistant.resolve_wazuh_server_factual_query(
            "Cho tôi thống kê cảnh báo trong 24h qua",
            self.mock_context
        )
        self.assertIsNotNone(res)
        self.assertIn("150", res)
        self.assertIn("Khẩn cấp (Critical)", res)
        self.assertIn("5", res)
        self.assertNotIn("/ /", res)

    def test_query_rule_lookup(self):
        res = self.assistant.resolve_wazuh_server_factual_query(
            "Quy tắc rule 5710 có ý nghĩa gì?",
            self.mock_context
        )
        self.assertIsNotNone(res)
        self.assertIn("5710", res)
        self.assertNotIn("/ /", res)

    def test_investigate_incident_returns_deterministic_answer_directly(self):
        result = self.assistant.investigate_incident(
            "danh sách agent hiện tại",
            system_context=self.mock_context
        )
        self.assertIn("summary", result)
        self.assertIn("ubuntu-dmz", result["summary"])
        self.assertEqual(result["reasoning_steps"][1]["title"], "Ground-Truth Verification")
