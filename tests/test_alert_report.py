from unittest.mock import Mock

from services.incident_assistant import IncidentAssistant
from services.wazuh_client import WazuhClient


def test_alert_stats_uses_exact_total_and_returns_report_breakdowns():
    response = Mock(status_code=200)
    response.json.return_value = {
        "hits": {"total": {"value": 16140, "relation": "eq"}},
        "aggregations": {
            "by_severity": {
                "buckets": [
                    {"key": "critical", "doc_count": 26},
                    {"key": "high", "doc_count": 1},
                    {"key": "medium", "doc_count": 111},
                    {"key": "low", "doc_count": 16002},
                ]
            },
            "hourly": {"buckets": [{"key_as_string": "10", "doc_count": 200}]},
            "top_rules": {
                "buckets": [{
                    "key": "40704",
                    "doc_count": 8,
                    "sample_alert": {
                        "hits": {"hits": [{"_source": {"rule": {"description": "Repeated service event"}}}]}
                    },
                }]
            },
            "top_agents": {"buckets": [{"key": "ubuntu-dmz", "doc_count": 100}]},
            "top_source_ips": {"buckets": [{"key": "10.0.0.50", "doc_count": 90}]},
        },
    }
    client = WazuhClient(host="127.0.0.1")
    session = Mock()
    session.post.return_value = response
    client._get_dashboard_session = Mock(return_value=session)

    stats = client.get_alert_stats_aggregated(hours_back=24)

    assert stats["total_24h"] == 16140
    assert stats["total_is_exact"] is True
    assert stats["critical"] + stats["high"] + stats["medium"] + stats["low"] == 16140
    assert stats["top_rules"][0]["rule_id"] == "40704"
    assert stats["top_agents"][0]["agent"] == "ubuntu-dmz"
    assert stats["top_source_ips"][0]["source_ip"] == "10.0.0.50"
    assert session.post.call_args.kwargs["json"]["track_total_hits"] is True


def test_24_hour_report_percentages_reconcile_and_explain_exact_source():
    assistant = IncidentAssistant()
    report = assistant.resolve_wazuh_server_factual_query(
        "Báo cáo 24h qua",
        {
            "status": "online",
            "wazuh_host": "127.0.0.1",
            "alert_stats": {
                "total_24h": 16140,
                "critical": 26,
                "high": 1,
                "medium": 111,
                "low": 16002,
                "hourly_local": {"17:00": 16000, "18:00": 140},
                "top_rules": [{"rule_id": "40704", "count": 8, "description": "Repeated service event"}],
                "top_agents": [{"agent": "ubuntu-dmz", "count": 100}],
                "top_source_ips": [{"source_ip": "10.0.0.50", "count": 90}],
            },
        },
    )

    assert "`16140` cảnh báo" in report
    assert "`10000` cảnh báo" not in report
    assert "0.2%" in report
    assert "0.0%" in report
    assert "0.7%" in report
    assert "99.1%" in report
    assert "Tổng số là số hit chính xác" in report
    assert "Khung giờ phát sinh nhiều nhất" in report
    assert "`40704`" in report


def test_24_hour_report_repairs_capped_total_from_severity_buckets():
    report = IncidentAssistant().resolve_wazuh_server_factual_query(
        "Báo cáo 24h qua",
        {"alert_stats": {
            "total_24h": 10000,
            "critical": 26,
            "high": 1,
            "medium": 111,
            "low": 16002,
        }},
    )

    assert "`16140` cảnh báo" in report
    assert "`10000` cảnh báo" not in report
    assert "0.2%" in report and "99.1%" in report
    assert "hit-count bị cap" in report
