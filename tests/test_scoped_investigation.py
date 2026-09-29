import unittest

from core.server import _alert_matches_scope, _select_analysis_alerts
from services.chat_intent import classify_chat_intent, is_security_related_query
from services.incident_assistant import IncidentAssistant


def _alert(alert_id, timestamp, rule_id, level, agent_id="009", agent_name="WIN-01"):
    return {
        "id": alert_id,
        "timestamp": timestamp,
        "rule": {"id": rule_id, "level": level, "description": rule_id},
        "agent": {"id": agent_id, "name": agent_name, "ip": "10.10.10.10"},
        "data": {},
    }


class ScopedInvestigationTests(unittest.TestCase):
    def test_scope_selector_keeps_local_attack_chain_and_excludes_other_device(self):
        alerts = [
            _alert("file", "2026-09-29T02:00:05Z", "554", 5),
            _alert("malware", "2026-09-29T02:00:06Z", "100050", 12),
            _alert("drop", "2026-09-29T02:00:13Z", "92213", 15),
            _alert("fortigate", "2026-09-29T02:00:07Z", "81619", 12, "010", "FortiGate"),
        ]
        scope = {"type": "device", "value": "agent_009"}

        self.assertTrue(all(_alert_matches_scope(item, scope) for item in alerts[:3]))
        self.assertFalse(_alert_matches_scope(alerts[-1], scope))
        selected = _select_analysis_alerts(alerts, scope, alerts[1])
        self.assertEqual([item["id"] for item in selected], ["file", "malware", "drop"])

    def test_scoped_rule_query_reaches_llm_instead_of_static_lookup(self):
        assistant = IncidentAssistant()
        assistant._call_pi_agent = lambda *args, **kwargs: "LLM_ANALYSIS"
        malware = _alert("malware", "2026-09-29T02:00:06Z", "100050", 12)

        result = assistant.investigate_incident(
            "Phân tích cụ thể nguy cơ từ log Rule 100050",
            alert_data=malware,
            scope_filter={"type": "device", "value": "agent_009"},
            recent_alerts=[malware],
            system_context={
                "status": "online",
                "host": "127.0.0.1",
                "agents": [],
                "alert_stats": {"total_24h": 1},
            },
        )

        self.assertEqual(result["layer_2_llm_reasoning"], "LLM_ANALYSIS")

    def test_wazuh_server_feature_question_is_not_server_status_lookup(self):
        assistant = IncidentAssistant()
        question = "trong wazuh server thì mục File Integrity Monitoring có nghĩa là gì"

        self.assertFalse(assistant._is_direct_wazuh_factual_query(question))
        self.assertIsNone(
            assistant.resolve_wazuh_server_factual_query(
                question,
                {"status": "online", "host": "127.0.0.1", "agents": [], "alert_stats": {}},
            )
        )

    def test_out_of_scope_query_is_blocked_before_llm(self):
        assistant = IncidentAssistant()
        llm_called = False

        def fail_if_called(*args, **kwargs):
            nonlocal llm_called
            llm_called = True
            return "SHOULD_NOT_BE_USED"

        assistant._call_pi_agent = fail_if_called
        result = assistant.investigate_incident(
            "cách làm món phở bò Hà Nội",
            system_context={"status": "online", "host": "127.0.0.1", "agents": [], "alert_stats": {}},
        )

        self.assertFalse(is_security_related_query("cách làm món phở bò Hà Nội"))
        self.assertEqual(result["layer_2_llm_reasoning"], "OUT_OF_SCOPE")
        self.assertFalse(llm_called)

    def test_security_followup_with_history_remains_allowed(self):
        assistant = IncidentAssistant()
        assistant._call_pi_agent = lambda *args, **kwargs: "LLM_ANALYSIS"

        result = assistant.investigate_incident(
            "nó có nghĩa là gì",
            conversation_history=[{"role": "user", "content": "File Integrity Monitoring trong Wazuh là gì?"}],
            system_context={"status": "online", "host": "127.0.0.1", "agents": [], "alert_stats": {}},
        )

        self.assertEqual(result["layer_2_llm_reasoning"], "LLM_ANALYSIS")

    def test_conversation_history_is_added_to_scoped_prompt(self):
        assistant = IncidentAssistant()
        captured = {}

        def fake_call(*args, **kwargs):
            captured["system_prompt"] = args[0]
            captured["user_prompt"] = args[1]
            return "LLM_ANALYSIS"

        assistant._call_pi_agent = fake_call
        malware = _alert("malware", "2026-09-29T02:00:06Z", "100050", 12)
        assistant.investigate_incident(
            "cảnh báo trên nói về điều gì",
            alert_data=malware,
            scope_filter={"type": "device", "value": "agent_009"},
            recent_alerts=[malware],
            conversation_history=[
                {"role": "user", "content": "Phân tích Rule 100050"},
                {"role": "ai", "content": "Đây là cảnh báo malware"},
            ],
            system_context={
                "status": "online",
                "host": "127.0.0.1",
                "agents": [],
                "alert_stats": {"total_24h": 1},
            },
        )

        self.assertIn("Phân tích Rule 100050", captured["user_prompt"])
        self.assertIn("cảnh báo trên", captured["system_prompt"])
        self.assertIn("7 giây", captured["system_prompt"])

    def test_24_hour_report_is_in_soc_scope_and_metrics_intent(self):
        query = "báo cáo 24h qua"
        self.assertTrue(is_security_related_query(query))
        self.assertEqual(classify_chat_intent(query)["intent"], "metrics")
        self.assertTrue(IncidentAssistant()._is_direct_wazuh_factual_query(query))

        assistant = IncidentAssistant()
        assistant._call_pi_agent = lambda *args, **kwargs: self.fail("24h report should use deterministic Wazuh metrics")
        result = assistant.investigate_incident(
            query,
            system_context={
                "status": "online",
                "host": "127.0.0.1",
                "agents": [],
                "alert_stats": {"total_24h": 12, "critical": 1, "high": 2, "medium": 5, "low": 4},
            },
        )
        self.assertIn("12", result["summary"])


if __name__ == "__main__":
    unittest.main()
