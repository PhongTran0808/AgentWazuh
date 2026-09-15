import json

from services.solpi_wazuh import WazuhSoLPi


def test_observation_pack_receipt_and_exact_paged_recall(tmp_path):
    pack = WazuhSoLPi(tmp_path)
    alert = {
        "id": "evt-1",
        "timestamp": "2026-09-15T00:00:00Z",
        "rule": {"id": "5710", "level": 10, "description": "SSH authentication failed"},
        "agent": {"name": "web-01"},
        "data": {"srcip": "10.10.1.50", "dstip": "10.10.1.10", "extra": "kept in archive"},
    }

    receipt = pack.build_investigation_package(
        "browser-session", "Investigate SSH failures", alert, None, {"status": "online"}
    )

    assert receipt.handle.startswith("wazuh-observation:sha256:")
    assert receipt.evidence[0]["rule_description"] == "SSH authentication failed"
    assert "extra" not in receipt.to_prompt_context()

    first_page = pack.read_observation(receipt.handle, offset=0, limit=80)
    assert first_page["next_offset"] == 80
    page = first_page
    restored = ""
    while page:
        restored += page["content"]
        page = pack.read_observation(receipt.handle, offset=page["next_offset"], limit=80) if page["next_offset"] is not None else None
    assert json.loads(restored)["alerts"][0]["data"]["extra"] == "kept in archive"


def test_online_context_is_bounded_and_excludes_raw_alert_payload(tmp_path):
    pack = WazuhSoLPi(tmp_path)
    alert = {"id": "evt-2", "rule": {"id": "100", "level": 3}, "data": {"raw_field": "raw-value"}}
    for index in range(8):
        pack.build_investigation_package("browser-session", f"question {index}", alert, None, {})

    context_files = list((tmp_path / "data" / "solpi_wazuh" / "contexts").glob("*.json"))
    stored_context = json.loads(context_files[0].read_text(encoding="utf-8"))
    assert len(stored_context) == 6
    assert stored_context[-1]["query"] == "question 7"
    assert "raw-value" not in json.dumps(stored_context)
