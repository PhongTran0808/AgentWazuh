import json
import unittest
from unittest.mock import MagicMock, patch

from ai.cloud_llm_analyzer import CloudLLMAnalyzer
from services.ip_anonymizer import IPAnonymizer


class TestIPAnonymizer(unittest.TestCase):
    def test_anonymize_and_deanonymize_internal_and_external_ips(self):
        anon = IPAnonymizer()
        raw = (
            "FortiGate detected brute-force from 172.16.100.10 to 10.10.30.10 "
            "and outbound DNS to 8.8.8.8. Localhost 127.0.0.1 and Wazuh 4.14.0 stay intact."
        )
        masked = anon.anonymize_text(raw)

        self.assertNotIn("172.16.100.10", masked)
        self.assertNotIn("10.10.30.10", masked)
        self.assertNotIn("8.8.8.8", masked)
        self.assertIn("IP_INTERNAL_1", masked)
        self.assertIn("IP_INTERNAL_2", masked)
        self.assertIn("IP_EXTERNAL_1", masked)
        self.assertIn("127.0.0.1", masked)
        self.assertIn("4.14.0", masked)

        restored = anon.deanonymize_text(masked)
        self.assertEqual(restored, raw)

    def test_deanonymize_does_not_corrupt_multi_digit_indices(self):
        anon = IPAnonymizer()
        ips = [f"10.10.10.{i}" for i in range(1, 13)]
        raw = " ".join(ips)
        masked = anon.anonymize_text(raw)
        self.assertIn("IP_INTERNAL_10", masked)
        self.assertEqual(anon.deanonymize_text(masked), raw)

    def test_cloud_llm_analyzer_masks_outbound_ips_and_restores_response(self):
        analyzer = CloudLLMAnalyzer()
        group = {
            "incident_id": "INC-TEST01",
            "entity": "172.16.100.10",
            "devices": ["FortiGate-VM", "WEB-01"],
            "source_ips": ["172.16.100.10"],
            "destination_ips": ["10.10.30.10"],
            "alerts": [
                {
                    "id": "a1",
                    "rule": {"id": "31101", "level": 12, "description": "Web shell"},
                    "agent": {"name": "WEB-01"},
                    "data": {"srcip": "172.16.100.10", "dstip": "10.10.30.10"},
                }
            ],
        }

        captured_payload = {}

        def fake_post(url, params=None, json=None, timeout=20):
            captured_payload["text"] = json["contents"][0]["parts"][0]["text"]
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            mock_resp.json.return_value = {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": (
                                        '{"incident_type": "Tấn công Web DMZ", '
                                        '"priority": "CRITICAL", "risk_score": 92, '
                                        '"mitre_techniques": ["T1505.003"], '
                                        '"summary": "IP_INTERNAL_1 tấn công IP_INTERNAL_2", '
                                        '"reasoning": "Trùng IP_INTERNAL_1 giữa FortiGate và WEB-01", '
                                        '"confidence": 0.95, "evidence_ids": ["a1"]}'
                                    )
                                }
                            ]
                        }
                    }
                ]
            }
            return mock_resp

        with patch.object(analyzer, "_api_key", return_value="fake-key"), \
             patch("ai.cloud_llm_analyzer.requests.post", side_effect=fake_post):
            result = analyzer.analyze_group(group)

        # Outbound Cloud API payload MUST NOT contain any real IPs
        self.assertNotIn("172.16.100.10", captured_payload["text"])
        self.assertNotIn("10.10.30.10", captured_payload["text"])
        self.assertIn("IP_INTERNAL_1", captured_payload["text"])
        self.assertIn("IP_INTERNAL_2", captured_payload["text"])

        # Returned analysis MUST have original IPs restored for the SOC Analyst
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["ip_anonymized_count"], 2)
        self.assertIn("172.16.100.10", result["analysis"]["summary"])
        self.assertIn("10.10.30.10", result["analysis"]["summary"])
        self.assertNotIn("IP_INTERNAL_1", result["analysis"]["summary"])


if __name__ == "__main__":
    unittest.main()
