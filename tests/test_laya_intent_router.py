"""Unit and Integration Tests for Laya Intent Classifier and Active Routing."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from services.laya_intent_router import (
    LAYA_INTENTS,
    classify_chat_intent_laya,
    get_laya_agent,
    route_intent,
)
from services.incident_assistant import IncidentAssistant


class TestLayaIntentRouter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Pre-warm model singleton for deterministic test execution
        cls.agent = get_laya_agent()

    def test_singleton_identity(self):
        """Ensure repeated get_laya_agent calls return the exact same singleton instance."""
        agent1 = get_laya_agent()
        agent2 = get_laya_agent()
        self.assertIsNotNone(agent1)
        self.assertIs(agent1, agent2)

    def test_route_all_nine_intents(self):
        """Verify each of the 9 standard intents is accurately classified by Laya."""
        test_cases = [
            ("Cho thống kê số alert critical trong 6 giờ vừa qua theo từng agent.", "stats"),
            ("Điều tra IP 203.0.113.88 đang xuất hiện trong nhiều alert, có phải tấn công có chủ đích không?", "investigate"),
            ("Viết rule phát hiện 8 lần đăng nhập RDP thất bại từ cùng IP trong 90 giây.", "create_rule"),
            ("Cho biết phiên bản Wazuh Manager và ruleset hiện đang chạy.", "wazuh_lookup"),
            ("Cập nhật cấu hình ossec.conf để bật syscheck.", "configure"),
            ("Tạo case sự cố gửi qua Jira.", "case_management"),
            ("Chặn IP 10.0.0.5 bằng Active Response ngay lập tức.", "response_action"),
            ("Hướng dẫn cài đặt Wazuh agent trên Ubuntu.", "support"),
            ("Cách nấu bún bò Huế ngon.", "out_of_scope"),
        ]

        for query, expected_intent in test_cases:
            with self.subTest(query=query, expected=expected_intent):
                res = route_intent(query)
                self.assertIn(res["intent"], LAYA_INTENTS)
                self.assertEqual(res["intent"], expected_intent)
                self.assertFalse(res["fallback_used"], f"Fallback should not be used for '{query}'")
                self.assertGreaterEqual(res["confidence"], 0.60)
                self.assertIn("latency_ms", res)
                self.assertIn("probabilities", res)

    def test_inference_latency_warm(self):
        """Verify warm inference latency is fast (< 150ms on GPU, < 1000ms on CPU)."""
        route_intent("Ping test")
        res = route_intent("Viết rule XML bắt sự kiện tắt Defender.")
        threshold = 150.0 if getattr(self.agent, "device", "cpu") == "cuda" else 1000.0
        self.assertLess(res["latency_ms"], threshold)

    def test_empty_query_safe_handling(self):
        """Verify empty or whitespace queries return safe support fallback without error."""
        res = route_intent("   ")
        self.assertEqual(res["intent"], "support")
        self.assertTrue(res["fallback_used"])

    def test_fallback_on_missing_model(self):
        """Verify graceful deterministic fallback when model path is invalid."""
        with patch.dict(os.environ, {"LAYA_MODEL_PATH": "/tmp/non_existent_model_dir"}):
            with patch("services.laya_intent_router._AGENT_SINGLETON", None):
                with patch("services.laya_intent_router._INIT_FAILED", False):
                    res = route_intent("Tạo rule phát hiện brute force SSH")
                    self.assertTrue(res["fallback_used"])
                    self.assertEqual(res["intent"], "create_rule")
                    self.assertIn("fallback", res["model_used"])

    def test_legacy_drop_in_compatibility(self):
        """Verify classify_chat_intent_laya provides backward-compatible output dictionary."""
        res = classify_chat_intent_laya("Tạo rule phát hiện brute force SSH")
        self.assertEqual(res["intent"], "rule_configuration")
        self.assertEqual(res["format"], "guided_steps_and_hitl_form")
        self.assertEqual(res["laya_intent"], "create_rule")

    def test_incident_assistant_out_of_scope_guard(self):
        """Verify IncidentAssistant strictly blocks out_of_scope queries."""
        assistant = IncidentAssistant()
        res = assistant.investigate_incident("Cách làm bánh chưng ngày Tết")
        self.assertEqual(res.get("layer_2_llm_reasoning"), "OUT_OF_SCOPE")
        self.assertEqual(res.get("intent_classification", {}).get("intent"), "out_of_scope")

    def test_greetings_hybrid_routing(self):
        """Verify greetings are deterministically routed to support with greeting legacy intent."""
        greetings = ["hello", "xin chào", "hello!", "hi", "chào bạn", "alo", "chào bot", "Hi there!"]
        for g in greetings:
            with self.subTest(greeting=g):
                res = route_intent(g)
                self.assertEqual(res["intent"], "support")
                self.assertFalse(res["fallback_used"])
                self.assertEqual(res.get("legacy_intent"), "greeting")
                self.assertIn("hybrid_deterministic", res.get("model_used", ""))

                compat = classify_chat_intent_laya(g)
                self.assertEqual(compat["intent"], "greeting")
                self.assertEqual(compat["laya_intent"], "support")
                self.assertEqual(compat["format"], "friendly_capabilities")
                self.assertEqual(compat.get("legacy_intent"), "greeting")

    def test_greeting_prefix_does_not_hide_substantive_query(self):
        """Verify a greeting followed by a real question is routed to the Laya classifier."""
        class FakeAgent:
            def predict(self, *_args, **_kwargs):
                return {
                    "answers": {
                        "intent": {
                            "choice": "stats",
                            "confidence": 0.95,
                            "probabilities": {"stats": 0.95},
                        }
                    }
                }

        query = "Hi, thống kê alert trong 24h qua"
        with patch("services.laya_intent_router.get_laya_agent", return_value=FakeAgent()):
            result = route_intent(query)

        self.assertEqual(result["intent"], "stats")
        self.assertNotEqual(result.get("legacy_intent"), "greeting")
        self.assertIn("laya_finetuned", result["model_used"])

    def test_incident_assistant_greetings_not_out_of_scope(self):
        """Verify IncidentAssistant handles greetings politely without triggering OUT_OF_SCOPE."""
        assistant = IncidentAssistant()
        greetings = ["hello", "xin chào", "hi", "chào bạn"]
        for g in greetings:
            with self.subTest(greeting=g):
                res = assistant.investigate_incident(g)
                reasoning = res.get("layer_2_llm_reasoning", "")
                self.assertNotEqual(reasoning, "OUT_OF_SCOPE")
                self.assertIn("Xin chào", reasoning)
                self.assertIn("Xin chào", res.get("summary", ""))
                self.assertEqual(res.get("threat_classification"), "INFORMATIONAL")

    def test_greeting_is_allowed_even_if_classifier_says_out_of_scope(self):
        """Verify the domain guard cannot block a recognized greeting due to a bad model result."""
        assistant = IncidentAssistant()
        result = assistant.investigate_incident(
            "hello",
            classified_intent={
                "intent": "out_of_scope",
                "legacy_intent": "general",
                "format": "direct_answer",
                "confidence": 0.99,
                "fallback_used": False,
            },
        )

        self.assertNotEqual(result["layer_2_llm_reasoning"], "OUT_OF_SCOPE")
        self.assertIn("Xin chào", result["summary"])

    def test_incident_assistant_greeting_prefix_keeps_real_question(self):
        """Verify greeting plus a substantive query does not get a greeting-only response."""
        assistant = IncidentAssistant()
        assistant._call_pi_agent = lambda *args, **kwargs: "INVESTIGATION_RESPONSE"

        result = assistant.investigate_incident("Hi, phân tích log đăng nhập bất thường trên server")

        self.assertEqual(result["layer_2_llm_reasoning"], "INVESTIGATION_RESPONSE")
        self.assertNotEqual(result["intent_classification"].get("legacy_intent"), "greeting")

    def test_incident_assistant_response_action_hitl_guard(self):
        """Verify IncidentAssistant blocks unapproved raw response action queries."""
        assistant = IncidentAssistant()
        res = assistant.investigate_incident("Chặn IP 10.0.0.5 bằng Active Response ngay lập tức.")
        self.assertEqual(res.get("threat_classification"), "CRITICAL")
        self.assertIn("HITL", res.get("summary", ""))
        self.assertEqual(res.get("intent_classification", {}).get("intent"), "response_action")


if __name__ == "__main__":
    unittest.main()
