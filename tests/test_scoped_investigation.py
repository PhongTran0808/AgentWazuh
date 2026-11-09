import unittest
from unittest.mock import patch, MagicMock

from core.server import _alert_matches_scope, _select_analysis_alerts
from services.chat_intent import classify_chat_intent, is_security_related_query
from services.incident_assistant import IncidentAssistant
from services.ollama_client import OllamaError


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

    def test_full_log_scan_marker_reaches_prompt_and_normalized_evidence(self):
        assistant = IncidentAssistant()
        captured = {}

        def fake_call(*args, **kwargs):
            captured["system_prompt"] = args[0]
            captured["user_prompt"] = args[1]
            return "SCAN_ANALYSIS"

        assistant._call_pi_agent = fake_call
        scan = _alert("scan", "2026-09-30T17:16:37.469+0700", "2501", 5, "008", "WEB-01")
        scan["location"] = "/var/log/portal_access.log"
        scan["full_log"] = (
            "[WEB_SCAN_DETECTED] User authentication failure from 127.0.0.1 "
            "- Directory enumeration probe detected (10 reqs)"
        )

        result = assistant.investigate_incident(
            "Phân tích nhóm sự cố scan",
            alert_data=scan,
            recent_alerts=[scan],
            incident_group={"incident_id": "INC-SCAN", "alerts": [scan]},
            system_context={
                "status": "online", "host": "127.0.0.1", "agents": [],
                "alert_stats": {"total_24h": 1},
            },
        )

        self.assertIn("Directory enumeration probe detected", captured["user_prompt"])
        self.assertIn("full_log", captured["system_prompt"])
        normalized = result["pipeline_evidence"]["normalized_by_python"][0]
        self.assertIn("WEB_SCAN_DETECTED", normalized["full_log"])
        self.assertEqual(normalized["location"], "/var/log/portal_access.log")
        self.assertIsNone(result["opensearch_payload"]["wazuh_ai_analysis"]["mitre_technique"])

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

    def test_incident_group_threat_classification_and_mitre_extraction(self):
        assistant = IncidentAssistant()
        assistant._call_pi_agent = lambda *args, **kwargs: "INCIDENT_ANALYSIS"

        alert1 = _alert("TT8kv6EBeVFFFqmMuiJr", "2026-11-09T14:10:12+0700", "554", 5)
        alert2 = _alert("Tj8kv6EBeVFFFqmMuiJr", "2026-11-09T14:10:14+0700", "100050", 12)
        alert2["rule"]["mitre"] = {
            "id": ["T1204.002"],
            "tactic": ["Execution"],
            "technique": ["Malicious File"],
        }
        incident_group = {
            "incident_id": "INC-B710C3B40CFD",
            "priority_score": 63,
            "risk_score": 63,
            "alerts": [alert1, alert2],
        }

        # Even if alert_data passed is alert1 (level 5), the incident analysis must evaluate the full group
        result = assistant.investigate_incident(
            "Phân tích nhóm sự cố INC-B710C3B40CFD (Điểm: 63/100)",
            alert_data=alert1,
            incident_group=incident_group,
            recent_alerts=[alert1, alert2],
            system_context={"status": "online", "host": "100.69.72.103", "agents": [], "alert_stats": {}},
        )

        self.assertEqual(result["threat_classification"], "TRUE_THREAT")
        self.assertNotEqual(result["threat_classification"], "FALSE_POSITIVE")
        self.assertEqual(result["opensearch_payload"]["wazuh_ai_analysis"]["threat_classification"], "TRUE_THREAT")
        self.assertLessEqual(result["opensearch_payload"]["wazuh_ai_analysis"]["false_positive_score"], 0.05)
        self.assertEqual(result["opensearch_payload"]["wazuh_ai_analysis"]["mitre_technique"], "T1204.002")

        # Check reasoning steps
        steps = result["reasoning_steps"]
        step1 = next(s for s in steps if s["step"] == 1)
        self.assertIn("INC-B710C3B40CFD", step1["detail"])
        self.assertIn("2 alerts", step1["detail"])

        step2 = next(s for s in steps if s["step"] == 2)
        self.assertEqual(step2["detail"], "Technique: T1204.002")

        step3 = next(s for s in steps if s["step"] == 3)
        self.assertEqual(step3["detail"], "TRUE_THREAT")

    def test_low_level_alert_is_not_classified_as_false_positive(self):
        assistant = IncidentAssistant()
        assistant._call_pi_agent = lambda *args, **kwargs: "ANALYSIS"

        low_alert = _alert("low_1", "2026-11-09T14:10:12+0700", "554", 5)
        result = assistant.investigate_incident(
            "Phân tích alert low_1",
            alert_data=low_alert,
            recent_alerts=[low_alert],
            system_context={"status": "online", "host": "100.69.72.103", "agents": [], "alert_stats": {}},
        )

        # Level 5 should be LOW_RISK, NOT FALSE_POSITIVE
        self.assertEqual(result["threat_classification"], "LOW_RISK")
        self.assertNotEqual(result["threat_classification"], "FALSE_POSITIVE")

    def test_multiturn_followup_with_history_allowed_and_injected(self):
        assistant = IncidentAssistant()
        captured = {}

        def fake_call(*args, **kwargs):
            captured["system_prompt"] = args[0]
            captured["user_prompt"] = args[1]
            return "FOLLOWUP_RESPONSE"

        assistant._call_pi_agent = fake_call
        history = [
            {"role": "user", "content": "Phân tích nhóm sự cố INC-B710C3B40CFD (Điểm: 63/100)"},
            {"role": "ai", "content": "Phát hiện mã độc VirusTotal trên WIN-01. Cần cách ly thiết bị."},
        ]

        # Follow-up query without explicit security keywords, relying on session memory
        result = assistant.investigate_incident(
            "tại sao lại như vậy?",
            conversation_history=history,
            system_context={"status": "online", "host": "100.69.72.103", "agents": [], "alert_stats": {}},
        )

        self.assertEqual(result["layer_2_llm_reasoning"], "FOLLOWUP_RESPONSE")
        self.assertIn("LỊCH SỬ HỘI THOẠI GẦN NHẤT", captured["user_prompt"])
        self.assertIn("INC-B710C3B40CFD", captured["user_prompt"])
        self.assertIn("Mạch đàm thoại đa lượt", captured["system_prompt"])

    @patch("services.incident_assistant.subprocess.run")
    @patch("services.incident_assistant.requests.post")
    def test_auto_model_fallback_pi_failure_to_gemini_api(self, mock_post, mock_subproc):
        # Pi CLI fails (e.g. exit code 1 or rate limit error)
        proc_mock = MagicMock()
        proc_mock.returncode = 1
        proc_mock.stdout = "Error: rate limit exceeded"
        proc_mock.stderr = "quota 429"
        mock_subproc.return_value = proc_mock

        # Direct Gemini API succeeds
        gemini_resp = MagicMock()
        gemini_resp.status_code = 200
        gemini_resp.json.return_value = {
            "candidates": [
                {"content": {"parts": [{"text": "Báo cáo phân tích từ Gemini API Fallback"}]}}
            ]
        }
        mock_post.return_value = gemini_resp

        assistant = IncidentAssistant()
        meta = {}
        result = assistant._call_pi_agent(
            "System prompt",
            "User query",
            alert_count=1,
            has_internal_ip=False,
            model_override="auto",
            execution_meta=meta,
        )

        self.assertEqual(result, "Báo cáo phân tích từ Gemini API Fallback")
        self.assertTrue(meta.get("fallback_used"))
        self.assertIn("Gemini API (Cloud Fallback)", meta.get("model_used"))

    @patch("services.incident_assistant.subprocess.run")
    @patch("services.incident_assistant.requests.post")
    @patch("services.incident_assistant.OllamaClient.generate")
    def test_auto_model_fallback_pi_and_cloud_failure_to_ollama(self, mock_ollama_gen, mock_post, mock_subproc):
        # Pi CLI fails
        proc_mock = MagicMock()
        proc_mock.returncode = 1
        proc_mock.stdout = "Pi CLI timeout"
        mock_subproc.return_value = proc_mock

        # Cloud APIs fail (HTTP 500 or network error)
        mock_post.side_effect = Exception("Cloud network unreachable")

        # Local Ollama succeeds
        mock_ollama_gen.return_value = "Báo cáo phân tích từ Ollama local fallback"

        assistant = IncidentAssistant()
        meta = {}
        result = assistant._call_pi_agent(
            "System prompt",
            "User query",
            alert_count=1,
            has_internal_ip=False,
            model_override="auto",
            execution_meta=meta,
        )

        self.assertEqual(result, "Báo cáo phân tích từ Ollama local fallback")
        self.assertTrue(meta.get("fallback_used"))
        self.assertIn("Ollama (Local Fallback)", meta.get("model_used"))

    @patch("services.incident_assistant.subprocess.run")
    @patch("services.incident_assistant.requests.post")
    @patch("services.incident_assistant.OllamaClient.generate")
    def test_auto_model_fallback_all_llms_failure_to_deterministic(self, mock_ollama_gen, mock_post, mock_subproc):
        # Pi CLI fails
        proc_mock = MagicMock()
        proc_mock.returncode = 1
        proc_mock.stdout = "Pi CLI error"
        mock_subproc.return_value = proc_mock

        # Cloud APIs fail
        mock_post.side_effect = Exception("Cloud network unreachable")

        # Local Ollama fails
        mock_ollama_gen.side_effect = OllamaError("Ollama connection refused")

        assistant = IncidentAssistant()
        result = assistant.investigate_incident(
            "Phân tích sự cố IP 100.69.72.103",
            model_override="auto",
            system_context={"status": "online", "host": "100.69.72.103", "agents": [], "alert_stats": {}},
        )

        self.assertTrue(result.get("fallback_used"))
        self.assertEqual(result.get("model_used"), "Deterministic SOC Rule Engine (Local Fallback)")
        self.assertEqual(result["pipeline_evidence"]["ai_analysis"]["model_used"], "Deterministic SOC Rule Engine (Local Fallback)")
        self.assertTrue(result["pipeline_evidence"]["ai_analysis"]["fallback_used"])
        self.assertTrue(len(result["layer_2_llm_reasoning"]) > 0)

    def test_wazuh_la_gi_knowledge_base_match(self):
        from services.wazuh_kb import render_wazuh_kb_answer
        ans = render_wazuh_kb_answer("wazuh là gì?")
        self.assertIsNotNone(ans)
        self.assertEqual(ans["topic_id"], "wazuh_overview")
        self.assertIn("SIEM", ans["markdown"])
        self.assertIn("XDR", ans["markdown"])

    def test_wazuh_la_gi_fallback_does_not_leak_agents_list(self):
        assistant = IncidentAssistant()
        system_context = {
            "status": "online",
            "host": "100.69.72.103",
            "agents": [
                {"id": "000", "name": "xinloihuy", "status": "active"},
                {"id": "001", "name": "SRV-01", "status": "active"},
            ],
            "alert_stats": {"total_24h": 0},
        }
        user_prompt_with_context = (
            "Bối cảnh Wazuh SIEM Dữ Liệu Thật:\n"
            "- Registered Active Agents Count: 2\n"
            "- DANH SÁCH THIẾT BỊ GIÁM SÁT CHÍNH THỨC\n\n"
            "Câu hỏi Analyst: wazuh là gì?"
        )
        res = assistant._generate_truthful_fallback(user_prompt_with_context, system_context)
        self.assertNotIn("BÁO CÁO DANH SÁCH WAZUH AGENT", res)
        self.assertIn("Wazuh", res)
        self.assertTrue("SIEM" in res or "nền tảng" in res)

    def test_investigate_incident_wazuh_la_gi(self):
        assistant = IncidentAssistant()
        result = assistant.investigate_incident(
            "wazuh là gì?",
            system_context={
                "status": "online",
                "host": "100.69.72.103",
                "agents": [
                    {"id": "000", "name": "xinloihuy", "status": "active"},
                ],
                "alert_stats": {"total_24h": 0},
            },
        )
        self.assertNotIn("BÁO CÁO DANH SÁCH WAZUH AGENT", result["summary"])
        self.assertIn("Wazuh", result["summary"])
        self.assertIn("SIEM", result["summary"])


if __name__ == "__main__":
    unittest.main()
