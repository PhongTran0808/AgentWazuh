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


