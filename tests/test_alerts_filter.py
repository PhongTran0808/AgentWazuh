"""
AgentWazuh — Alert Filter API Test Suite
========================================
Kiểm tra GET /api/wazuh/alerts/filter:
1. type=device chỉ trả về log của đúng thiết bị đó.
2. type=device không khớp thì trả về rỗng (KHÔNG fallback về toàn bộ cache).
3. type=severity giữ nguyên hành vi cũ (fallback toàn bộ cache khi không khớp).
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from fastapi.testclient import TestClient
import core.server as server
from core.server import app

client = TestClient(app)

auth_res = client.post("/api/auth/login", json={
    "username": "admin",
    "password": "admin123",
    "wazuh_host": "172.16.175.145",
    "wazuh_port": 55000
})
assert auth_res.status_code == 200, f"Login failed: {auth_res.text}"
cookies = auth_res.cookies

SAMPLE_ALERTS = [
    {
        "timestamp": "2026-09-17T10:00:00Z",
        "rule": {"id": "5710", "level": 5, "description": "sshd: attempt to login using a denied user"},
        "agent": {"id": "001", "name": "web-01", "ip": "172.16.0.5"},
        "data": {"srcip": "10.0.0.9"},
    },
    {
        "timestamp": "2026-09-17T10:01:00Z",
        "rule": {"id": "5712", "level": 14, "description": "sshd: brute force"},
        "agent": {"id": "002", "name": "db-01", "ip": "172.16.0.6"},
        "data": {"srcip": "10.0.0.9"},
    },
]


def _with_cache(alerts):
    server.GLOBAL_ALERTS_CACHE = alerts


def test_device_filter_matches_by_agent_ip():
    _with_cache(SAMPLE_ALERTS)
    res = client.get("/api/wazuh/alerts/filter", params={"type": "device", "value": "172.16.0.6"}, cookies=cookies)
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 1
    assert data["alerts"][0]["rule"]["id"] == "5712"


def test_device_filter_matches_by_agent_id_and_srcip():
    _with_cache(SAMPLE_ALERTS)
    for value, expected in (("001", 1), ("10.0.0.9", 2)):
        data = client.get("/api/wazuh/alerts/filter", params={"type": "device", "value": value}, cookies=cookies).json()
        assert data["count"] == expected, f"value={value}"


def test_device_filter_does_not_fall_back_to_all_alerts():
    _with_cache(SAMPLE_ALERTS)
    data = client.get("/api/wazuh/alerts/filter", params={"type": "device", "value": "172.16.99.99"}, cookies=cookies).json()
    assert data["count"] == 0
    assert data["alerts"] == []


def test_legacy_severity_filter_keeps_fallback():
    _with_cache(SAMPLE_ALERTS)
    high = client.get("/api/wazuh/alerts/filter", params={"type": "severity", "value": "high"}, cookies=cookies).json()
    assert high["count"] == 1
    assert high["alerts"][0]["rule"]["level"] == 14

    # severity=critical có 0 log khớp -> fallback toàn bộ cache (hành vi legacy giữ nguyên).
    critical = client.get("/api/wazuh/alerts/filter", params={"type": "severity", "value": "critical"}, cookies=cookies).json()
    assert critical["count"] == 0
    assert len(critical["alerts"]) == len(SAMPLE_ALERTS)

    legacy = client.get("/api/wazuh/alerts/filter", params={"type": "agent", "value": "anything"}, cookies=cookies).json()
    assert legacy["count"] == len(SAMPLE_ALERTS)
