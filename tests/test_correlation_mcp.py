import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
from mcp_layer.correlation_mcp import OpenSearchCorrelationTool, search_correlated_events
from services.incident_assistant import IncidentAssistantService

class TestOpenSearchCorrelationTool(unittest.TestCase):

    def setUp(self):
        self.tool = OpenSearchCorrelationTool(host="127.0.0.1", port=9200)

    def test_parse_timestamp_and_dsl_query(self):
        base_ts = "2026-09-07T16:00:00.000Z"
        target_ip = "172.16.10.50"
        
        base_dt = self.tool._parse_timestamp(base_ts)
        start_iso = self.tool._format_iso(base_dt - timedelta(minutes=15))
        end_iso = self.tool._format_iso(base_dt + timedelta(minutes=15))

        dsl = self.tool.build_dsl_query(target_ip, start_iso, end_iso)

        self.assertIn("query", dsl)
        self.assertEqual(dsl["size"], 100)
        
        must_clauses = dsl["query"]["bool"]["must"]
        range_clause = must_clauses[0]["range"]["@timestamp"]
        
        self.assertIn("2026-09-07T15:45:00", range_clause["gte"])
        self.assertIn("2026-09-07T16:15:00", range_clause["lte"])

    @patch.object(OpenSearchCorrelationTool, 'query_opensearch')
    def test_search_correlated_events_with_hits(self, mock_query):
        mock_hits = [
            {
                "_source": {
                    "@timestamp": "2026-09-07T16:02:10.000Z",
                    "agent": {"name": "Firewall-pfSense", "ip": "172.16.0.1"},
                    "rule": {"id": "100010", "level": 10, "description": "Firewall block external scan"},
                    "data": {"srcip": "172.16.10.50", "dstip": "192.168.1.208"}
                }
            },
            {
                "_source": {
                    "@timestamp": "2026-09-07T16:05:30.000Z",
                    "agent": {"name": "PC-PB1-VLAN10", "ip": "172.16.10.10"},
                    "rule": {"id": "100015", "level": 12, "description": "SSH Brute Force Success"},
                    "data": {"srcip": "172.16.10.50", "dstip": "172.16.10.10"}
                }
            }
        ]
        mock_query.return_value = mock_hits

        events = self.tool.search_correlated_events(
            target_ip="172.16.10.50",
            base_timestamp="2026-09-07T16:00:00Z",
            time_window_minutes=15
        )

        self.assertIsInstance(events, list)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["agent.name"], "Firewall-pfSense")
        self.assertEqual(events[0]["rule.id"], "100010")
        self.assertEqual(events[1]["agent.name"], "PC-PB1-VLAN10")

    @patch.object(OpenSearchCorrelationTool, 'query_opensearch')
    def test_search_correlated_events_empty_fallback(self, mock_query):
        mock_query.return_value = []

        result = self.tool.search_correlated_events(
            target_ip="172.16.10.99",
            base_timestamp="2026-09-07T16:00:00Z"
        )

        expected_msg = "Không ghi nhận hoạt động tương quan nào từ IP này trên các thiết bị khác trong khoảng thời gian +/- 15 phút."
        self.assertEqual(result, expected_msg)


class TestIncidentAssistantService(unittest.TestCase):

    def setUp(self):
        self.mock_tool = MagicMock(spec=OpenSearchCorrelationTool)
        self.service = IncidentAssistantService(correlation_tool=self.mock_tool)

    def test_analyze_incident_high_level_triggers_correlation(self):
        self.mock_tool.search_correlated_events.return_value = [
            {
                "timestamp": "2026-09-07T16:02:00Z",
                "agent.name": "Firewall-pfSense",
                "rule.id": "100010",
                "rule.level": 10,
                "rule.description": "Port scan blocked",
                "srcip": "172.16.10.50",
                "dstip": "172.16.0.1"
            },
            {
                "timestamp": "2026-09-07T16:08:00Z",
                "agent.name": "PC-PB1-VLAN10",
                "rule.id": "100015",
                "rule.level": 12,
                "rule.description": "SSH Brute Force",
                "srcip": "172.16.10.50",
                "dstip": "172.16.10.10"
            }
        ]

        alert = {
            "rule": {"id": "100015", "level": 12, "description": "SSH Brute Force attack"},
            "agent": {"name": "PC-PB1-VLAN10"},
            "data": {"srcip": "172.16.10.50", "dstip": "172.16.10.10"},
            "timestamp": "2026-09-07T16:00:00Z"
        }

        res = self.service.analyze_incident(alert)

        self.assertTrue(res["correlation_triggered"])
        self.assertEqual(len(res["correlated_events"]), 2)
        
        briefing = res["briefing_report"]
        self.assertIn("🔗 Phân Tích Tương Quan Đa Thiết Bị (Cross-Device Activity)", briefing)
        self.assertIn("Attacker IP (172.16.10.50) ➔ Firewall Gateway ➔ Multilayer Switch ➔ VLAN 10", briefing)
        self.assertIn("Firewall-pfSense", briefing)
        self.assertIn("PC-PB1-VLAN10", briefing)

    def test_analyze_incident_high_level_empty_correlation_fallback(self):
        self.mock_tool.search_correlated_events.return_value = "Không ghi nhận hoạt động tương quan nào từ IP này trên các thiết bị khác trong khoảng thời gian +/- 15 phút."

        alert = {
            "rule": {"id": "100010", "level": 11, "description": "Sudo Privilege Escalation"},
            "agent": {"name": "PC-PB2-VLAN20"},
            "data": {"srcip": "172.16.20.40", "dstip": "172.16.20.1"},
            "timestamp": "2026-09-07T16:00:00Z"
        }

        res = self.service.analyze_incident(alert)

        self.assertTrue(res["correlation_triggered"])
        self.assertEqual(len(res["correlated_events"]), 0)
        
        briefing = res["briefing_report"]
        self.assertIn("🔗 Phân Tích Tương Quan Đa Thiết Bị (Cross-Device Activity)", briefing)
        self.assertIn("Không ghi nhận hoạt động tương quan nào từ IP này trên các thiết bị khác trong khoảng thời gian +/- 15 phút.", briefing)


if __name__ == "__main__":
    unittest.main()
