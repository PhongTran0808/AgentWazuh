import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from services.incident_assistant import IncidentAssistant
from services.ollama_client import OllamaClient, model_name_from_selection, tags_url


class OllamaClientTests(unittest.TestCase):
    def test_model_selection_preserves_slashes_inside_local_model_name(self):
        self.assertEqual(model_name_from_selection("ollama/qwen2.5:7b"), "qwen2.5:7b")
        self.assertEqual(
            model_name_from_selection("ollama/OpenNix/wazuh-llama:latest"),
            "OpenNix/wazuh-llama:latest",
        )

    def test_tags_url_reuses_configured_generate_endpoint(self):
        self.assertEqual(
            tags_url("http://localhost:11434/api/generate"),
            "http://localhost:11434/api/tags",
        )

    @patch("services.ollama_client.requests.post")
    def test_generate_uses_native_generate_api(self, post):
        response = Mock(status_code=200)
        response.json.return_value = {"response": "Báo cáo local"}
        post.return_value = response

        result = OllamaClient(timeout_seconds=12).generate("system", "user", "qwen2.5:7b")

        self.assertEqual(result, "Báo cáo local")
        payload = post.call_args.kwargs["json"]
        self.assertEqual(payload["model"], "qwen2.5:7b")
        self.assertIn("system", payload["system"])
        self.assertFalse(payload["stream"])
        self.assertEqual(post.call_args.kwargs["timeout"], 12.0)

    @patch("services.ollama_client.requests.post")
    def test_incident_assistant_routes_explicit_ollama_selection_without_pi(self, post):
        response = Mock(status_code=200)
        response.json.return_value = {"response": "Phản hồi từ Qwen local"}
        post.return_value = response

        with tempfile.TemporaryDirectory() as temp_dir:
            assistant = IncidentAssistant()
            assistant.base_dir = Path(temp_dir)
            result = assistant._call_pi_agent(
                "system",
                "user",
                0,
                False,
                {"status": "online"},
                model_override="ollama/qwen2.5:7b",
            )

        self.assertEqual(result, "Phản hồi từ Qwen local")
        self.assertEqual(post.call_args.kwargs["json"]["model"], "qwen2.5:7b")


if __name__ == "__main__":
    unittest.main()
