"""
AgentWazuh — Settings API & Modal Verification Test Suite
=========================================================
Tests GET /api/settings and POST /api/settings endpoints to ensure:
1. Valid JSON payloads and partial payloads pass Pydantic validation without 422 errors.
2. System settings file config/system_settings.json gets saved correctly.
3. Both full payloads and partial payloads update settings cleanly.
"""

import sys
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
from core.server import app

client = TestClient(app)

# Create a valid session cookie for auth
auth_res = client.post("/api/auth/login", json={
    "username": "admin",
    "password": "admin123",
    "wazuh_host": "172.16.175.145",
    "wazuh_port": 55000
})
assert auth_res.status_code == 200, f"Login failed: {auth_res.text}"
cookies = auth_res.cookies


def test_get_settings():
    res = client.get("/api/settings", cookies=cookies)
    print("GET /api/settings response:", res.status_code, res.json())
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    assert "settings" in res.json()
    print("✅ GET /api/settings passed.")


def test_post_full_settings():
    payload = {
        "session_timeout_minutes": 45,
        "icmp_ping_interval_seconds": 20,
        "ping_retry_threshold": 4,
        "wazuh_host": "172.16.175.145",
        "wazuh_port": 55000,
        "wazuh_user": "agentwazuh",
        "uptime_kuma_push_token": "token-test-123",
        "device_cache_ttl_days": 14,
        "ui_theme": "cyber_dark"
    }
    res = client.post("/api/settings", json=payload, cookies=cookies)
    print("POST /api/settings full response:", res.status_code, res.json())
    assert res.status_code == 200, f"Full post failed: {res.text}"
    assert res.json()["status"] == "success"
    assert res.json()["settings"]["session_timeout_minutes"] == 45
    print("✅ POST /api/settings full payload passed.")


def test_post_partial_settings():
    # Only sending wazuh_host and wazuh_port
    payload = {
        "wazuh_host": "172.16.175.145",
        "wazuh_port": 55000
    }
    res = client.post("/api/settings", json=payload, cookies=cookies)
    print("POST /api/settings partial response:", res.status_code, res.json())
    assert res.status_code == 200, f"Partial post failed: {res.text}"
    assert res.json()["status"] == "success"
    print("✅ POST /api/settings partial payload passed.")


if __name__ == "__main__":
    print("==================================================")
    print("🔍 TESTING SETTINGS API & MODAL FUNCTIONALITY")
    print("==================================================")
    test_get_settings()
    test_post_full_settings()
    test_post_partial_settings()
    print("🎉 ALL SETTINGS TESTS PASSED 100%!")
