import re
import json
import ipaddress
from pathlib import Path
from typing import Dict, Any, List, Tuple

class DynamicAITopologyParser:
    """
    Dynamic Real-Time Topology Engine (Version 14.0 Enterprise):
    - Strictly real-time discovery (No mock or hardcoded topology data).
    - If no active devices are detected from Wazuh API, returns clean Empty State.
    """

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent

    def build_dynamic_topology(self, raw_device_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not raw_device_data:
            return {
                "nodes": [],
                "edges": [],
                "empty_state": True,
                "message": "Chưa phát hiện thiết bị kết nối. Đang chờ kết nối từ Wazuh Agent."
            }

        nodes = {}
        subnet_map: Dict[str, List[str]] = {}

        # 1. Catalog Real Nodes & Extract Interfaces
        for dev in raw_device_data:
            ip = dev.get("ip")
            if not ip:
                continue

            node_id = f"node_{ip.replace('.', '_')}"
            nodes[ip] = {
                "id": node_id,
                "label": f"{dev.get('name', 'Device')}\n({ip})",
                "group": dev.get("type", "pc"),
                "ip": ip,
                "secondary_ip": dev.get("secondary_ip"),
                "os": dev.get("os", "Linux / Network OS"),
                "device_type": dev.get("type", "device").upper(),
                "agent_status": dev.get("verified_by", "Wazuh Agent Active"),
                "open_ports": dev.get("interfaces", ["Real Active Net"]),
                "tier": 0,
                "verified": True
            }

            all_ips = [ip]
            if dev.get("secondary_ip"):
                all_ips.append(dev.get("secondary_ip"))

            for single_ip in all_ips:
                try:
                    ip_obj = ipaddress.ip_interface(f"{single_ip}/24")
                    subnet_str = str(ip_obj.network)
                    if subnet_str not in subnet_map:
                        subnet_map[subnet_str] = []
                    if ip not in subnet_map[subnet_str]:
                        subnet_map[subnet_str].append(ip)
                except Exception:
                    pass

        if not nodes:
            return {
                "nodes": [],
                "edges": [],
                "empty_state": True,
                "message": "Chưa phát hiện thiết bị kết nối. Đang chờ kết nối từ Wazuh Agent."
            }

        # 2. Build Dynamic Edges Across Subnets
        edges = []
        edge_set = set()

        for subnet_str, ip_list in subnet_map.items():
            if len(ip_list) > 1:
                for i in range(len(ip_list) - 1):
                    ip1 = ip_list[i]
                    ip2 = ip_list[i + 1]
                    pair_key = tuple(sorted([ip1, ip2]))
                    if pair_key not in edge_set:
                        edge_set.add(pair_key)
                        edges.append({
                            "from": nodes[ip1]["id"],
                            "to": nodes[ip2]["id"],
                            "label": f"Subnet {subnet_str}",
                            "arrows": "to;from"
                        })

        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "empty_state": False,
            "message": "🟢 Đã tìm thấy các thiết bị đang hoạt động trên hệ thống."
        }

if __name__ == "__main__":
    parser = DynamicAITopologyParser()
    res = parser.build_dynamic_topology([])
    print("🟢 Pure Real-Time Topology Output (No Devices):")
    print(json.dumps(res, indent=2))
