"""
AgentWazuh — Ghost Nodes & Endpoint Isolation Verification Suite
================================================================
Verifies that:
1. Interacting with inventory confirmation, alert imports, or topology parser endpoints
   NEVER injects ghost/phantom nodes into the topology map or Wazuh Server.
2. Topology ONLY renders devices that exist in Wazuh Manager REST API 55000 (Agent Registry).
3. Confirming devices or importing raw logs does NOT pollute the topology graph.
"""

import sys
import json
import asyncio
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.server import (
    _get_security_map_devices,
    build_ai_dynamic_topology,
    GLOBAL_SYSTEM_STATUS_CACHE,
    GLOBAL_ALERTS_CACHE,
    save_known_device,
    load_known_devices_dict
)


def test_1_empty_agent_state():
    """
    Test 1: When no agents are registered in Wazuh Server,
    topology map MUST return ONLY the central Wazuh Server node (0 ghost nodes).
    """
    # Simulate zero active agents in Wazuh Server
    GLOBAL_SYSTEM_STATUS_CACHE["agents"] = []

    devices = _get_security_map_devices()
    print(f"Test 1 — Security Map devices count: {len(devices)}")
    assert len(devices) == 1, f"Expected 1 node (Wazuh Server), got {len(devices)}"
    assert devices[0]["id"] == "wazuh_manager_node", "First node must be Wazuh Server"

    topo = build_ai_dynamic_topology()
    print(f"Test 1 — AI Dynamic Topology empty_state: {topo.get('empty_state')}")
    assert topo.get("empty_state") == True, "Topology must be empty_state=True when 0 agents exist"
    assert len(topo.get("nodes", [])) == 0, "Nodes array must be empty"
    print("✅ TEST 1 PASSED: Zero ghost nodes when 0 agents registered.")


def test_2_inventory_confirm_isolation():
    """
    Test 2: Confirming a device in inventory MUST NOT cause it to appear on topology
    unless it actually becomes registered in Wazuh Server Agent Registry.
    """
    # Simulate user confirming an unverified infrastructure device
    mock_device = {
        "ip": "192.168.99.99",
        "name": "Unregistered-Phantom-Router",
        "type": "router",
        "role": "infrastructure_device",
        "verified_by": "manual"
    }
    save_known_device(mock_device)

    # Ensure Wazuh Server active agents list is still empty
    GLOBAL_SYSTEM_STATUS_CACHE["agents"] = []

    devices = _get_security_map_devices()
    print(f"Test 2 — Devices count after inventory confirm: {len(devices)}")

    # Node count MUST remain 1 (Wazuh Server only) — Unregistered-Phantom-Router MUST NOT appear
    agent_ids = [d["id"] for d in devices]
    assert len(devices) == 1, f"Expected 1 node, got {len(devices)}: {agent_ids}"
    assert "dev_192.168.99.99" not in agent_ids, "Phantom router MUST NOT be in topology!"

    topo = build_ai_dynamic_topology()
    assert topo.get("empty_state") == True, "Topology must remain empty_state=True"
    print("✅ TEST 2 PASSED: Inventory confirm does NOT create ghost nodes on topology.")


def test_3_alert_import_isolation():
    """
    Test 3: Importing raw alert JSONs containing random source IPs or unknown agent names
    MUST NOT inject fake nodes into the topology map.
    """
    GLOBAL_SYSTEM_STATUS_CACHE["agents"] = []
    fake_alert = {
        "id": "test_import_999",
        "timestamp": "2026-08-24T14:00:00.000Z",
        "agent": {"id": "999", "name": "Fake-Attacker-Host", "ip": "10.250.250.250"},
        "rule": {"id": "100100", "level": 14, "description": "Malicious payload detected"},
        "data": {"srcip": "10.250.250.250", "dstip": "192.168.1.1"}
    }
    GLOBAL_ALERTS_CACHE.insert(0, fake_alert)

    devices = _get_security_map_devices()
    print(f"Test 3 — Devices count after raw alert import: {len(devices)}")
    assert len(devices) == 1, f"Expected 1 node, got {len(devices)}"

    topo = build_ai_dynamic_topology()
    assert topo.get("empty_state") == True, "Topology must remain empty_state=True"
    print("✅ TEST 3 PASSED: Raw alert import does NOT pollute topology graph.")


def test_4_real_agent_registration_flow():
    """
    Test 4: When a REAL agent registers with Wazuh Server API 55000,
    it MUST immediately appear on the topology map with full metadata.
    """
    # Simulate a real Wazuh agent registering
    GLOBAL_SYSTEM_STATUS_CACHE["agents"] = [
        {
            "id": "001",
            "name": "Ubuntu-Agent-Prod",
            "ip": "10.10.10.2",
            "status": "active",
            "os": {"name": "Ubuntu 22.04 LTS"}
        }
    ]

    devices = _get_security_map_devices()
    print(f"Test 4 — Devices count after real agent registration: {len(devices)}")
    assert len(devices) == 2, f"Expected 2 nodes (Server + Agent), got {len(devices)}"

    dev_names = [d["name"] for d in devices]
    assert "Wazuh Server" in dev_names, "Wazuh Server must be present"
    assert "Ubuntu-Agent-Prod" in dev_names, "Ubuntu-Agent-Prod must be present"

    agent_node = next(d for d in devices if d["id"] == "agent_001")
    assert agent_node["ip"] == "10.10.10.2"
    assert agent_node["verified"] == True
    assert agent_node["source"] == "wazuh_server_api"

    topo = build_ai_dynamic_topology()
    assert topo.get("empty_state") == False, "Topology must be active (empty_state=False)"
    assert len(topo.get("nodes", [])) == 1, "Topology parser must return 1 node"
    print("✅ TEST 4 PASSED: Real registered agent appears correctly on topology.")


if __name__ == "__main__":
    print("===============================================================")
    print("🔍 RUNNING GHOST NODES & ENDPOINT ISOLATION VERIFICATION SUITE")
    print("===============================================================")
    test_1_empty_agent_state()
    test_2_inventory_confirm_isolation()
    test_3_alert_import_isolation()
    test_4_real_agent_registration_flow()
    print()
    print("🎉 ALL 4 ISOLATION TESTS PASSED 100%! ZERO GHOST NODES GUARANTEED.")
