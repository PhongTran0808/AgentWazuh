from types import SimpleNamespace

from fastapi.testclient import TestClient

import core.server as server
from services.incident_assistant import IncidentAssistant
from services.wazuh_client import WazuhClient


def test_dashboard_is_server_side_protected():
    client = TestClient(server.app, follow_redirects=False)

    for path in ("/dashboard", "/static/dashboard.html"):
        response = client.get(path)
        assert response.status_code == 302
        assert response.headers["location"] == "/login"


def test_nonexistent_alert_id_returns_404_without_fallback():
    client = TestClient(server.app)
    original_cache = server.GLOBAL_ALERTS_CACHE
    original_overrides = dict(server.app.dependency_overrides)
    server.GLOBAL_ALERTS_CACHE = [{"id": "known-alert", "rule": {"id": "5710"}}]
    server.app.dependency_overrides[server.require_authenticated_session] = lambda: "test-session"
    try:
        response = client.post(
            "/api/wazuh/investigate",
            json={"query": "phân tích alert", "alert_id": "NON_EXISTENT_9999"},
        )
    finally:
        server.GLOBAL_ALERTS_CACHE = original_cache
        server.app.dependency_overrides = original_overrides

    assert response.status_code == 404
    assert "NON_EXISTENT_9999" in response.json()["detail"]


def test_rule_lookup_does_not_assume_custom_rule():
    assistant = IncidentAssistant()

    missing = assistant.resolve_wazuh_server_factual_query(
        "Giải thích Rule 999999", {}, rule_lookup={"status": "not_found", "rule_id": "999999"}
    )
    unavailable = assistant.resolve_wazuh_server_factual_query(
        "Giải thích Rule 100050",
        {},
        rule_lookup={"status": "unavailable", "rule_id": "100050", "error": "timeout"},
    )

    assert "KHÔNG TÌM THẤY RULE" in missing
    assert "Custom Rule" not in missing
    assert "CHƯA THỂ XÁC MINH RULE" in unavailable
    assert "Custom Rule" not in unavailable


def test_wazuh_rule_api_distinguishes_missing_from_unavailable():
    client = WazuhClient(host="127.0.0.1")

    client._request_with_auth_retry = lambda *args, **kwargs: SimpleNamespace(
        status_code=200,
        json=lambda: {"data": {"affected_items": [{"id": 100050, "description": "Malware detected"}]}},
    )
    assert client.get_rule_definition("100050")["status"] == "found"

    client._request_with_auth_retry = lambda *args, **kwargs: SimpleNamespace(
        status_code=200,
        json=lambda: {"data": {"affected_items": []}},
    )
    assert client.get_rule_definition("999999")["status"] == "not_found"

    client._request_with_auth_retry = lambda *args, **kwargs: None
    assert client.get_rule_definition("100050")["status"] == "unavailable"
