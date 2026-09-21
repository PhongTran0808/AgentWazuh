import json

from ai.gemini_analyzer import GeminiAnalyzer


def test_parse_plain_json_response():
    result = GeminiAnalyzer.parse_json_response('{"priority":"HIGH","risk_score":80}')
    assert result["priority"] == "HIGH"
    assert result["risk_score"] == 80


def test_parse_fenced_json_response():
    result = GeminiAnalyzer.parse_json_response('```json\n{"incident_type":"SSH brute force"}\n```')
    assert result["incident_type"] == "SSH brute force"


def test_missing_key_returns_explicit_unavailable():
    analyzer = GeminiAnalyzer(base_dir="/tmp/agentwazuh-test-without-config")
    result = analyzer.analyze_group({"incident_id": "INC-1", "alerts": []})
    assert result["status"] == "unavailable"
    assert result["provider"] == "gemini"

