import os
import sys
import json
import importlib.util
from typing import Dict, Any, List, Union, Optional
from mcp_layer.correlation_mcp import OpenSearchCorrelationTool

def _load_system_prompt() -> str:
    pi_prompt_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".pi", "system_prompt.py")
    if os.path.exists(pi_prompt_path):
        spec = importlib.util.spec_from_file_location("pi_system_prompt", pi_prompt_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.get_system_prompt()
    return "SOC Incident Investigation Assistant System Prompt"


class IncidentAssistantService:
    """
    SOC Incident Assistant Service:
    Orchestrates alert triage, retro-hunting via search_correlated_events MCP tool,
    network topology mapping, and SOC Briefing report generation.
    """

    TOPOLOGY_ZONES = {
        "VLAN 10": ["172.16.10.", "vlan10", "floor1", "pc-vlan10"],
        "VLAN 20": ["172.16.20.", "vlan20", "floor2", "pc-vlan20"],
        "VLAN 30": ["172.16.30.", "vlan30", "floor3", "pc-vlan30"],
        "VLAN 99": ["172.16.99.", "192.168.1.", "vlan99", "manager", "wazuh-server", "server"],
        "Firewall Gateway": ["172.16.0.1", "192.168.1.1", "fw", "firewall", "pfsense", "fortigate"],
        "Edge Router": ["172.16.0.254", "router", "gateway"],
        "Multilayer Switch": ["switch", "l3switch", "core-switch"]
    }

    def __init__(self, correlation_tool: Optional[OpenSearchCorrelationTool] = None):
        self.correlation_tool = correlation_tool or OpenSearchCorrelationTool()
        self.system_prompt = _load_system_prompt()


    def resolve_network_zone(self, ip_or_name: str) -> str:
        """Maps an IP or agent name to the corresponding network topology zone."""
        val = str(ip_or_name).lower()
        for zone, keywords in self.TOPOLOGY_ZONES.items():
            if any(kw in val for kw in keywords):
                return zone
        return "Unknown Network Zone"

    def build_attack_flow_diagram(self, target_ip: str, events: List[Dict[str, Any]]) -> str:
        """Builds a clear text flow diagram representing cross-device movement."""
        path_nodes = [f"Attacker ({target_ip})"]
        
        # Traverse events to detect traversed nodes/zones
        visited_zones = set()
        visited_zones.add("Firewall Gateway") # Edge traffic enters via Gateway
        visited_zones.add("Multilayer Switch") # Routed via Layer 3 Switch

        for ev in events:
            agent = ev.get("agent.name", "")
            dstip = ev.get("dstip", "")
            zone_agent = self.resolve_network_zone(agent)
            zone_dst = self.resolve_network_zone(dstip)
            
            if zone_agent != "Unknown Network Zone":
                visited_zones.add(zone_agent)
            if zone_dst != "Unknown Network Zone":
                visited_zones.add(zone_dst)

        # Standard network sequence: Firewall -> Multilayer Switch -> Targeted VLANs
        ordered_flow = [f"Attacker IP ({target_ip})", "Firewall Gateway", "Multilayer Switch"]
        for z in ["VLAN 10", "VLAN 20", "VLAN 30", "VLAN 99"]:
            if z in visited_zones:
                ordered_flow.append(z)

        return " ➔ ".join(ordered_flow)

    def analyze_incident(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes a security alert:
        - If Level >= 10, automatically triggers search_correlated_events.
        - Generates SOC Incident Briefing with cross-device correlation report.
        """
        rule_info = alert_data.get("rule", {})
        rule_level = rule_info.get("level", 0)
        rule_id = rule_info.get("id", "N/A")
        rule_desc = rule_info.get("description", "Security Event Triggered")

        data_info = alert_data.get("data", {})
        agent_info = alert_data.get("agent", {})
        
        src_ip = data_info.get("srcip") or alert_data.get("srcip") or agent_info.get("ip") or "127.0.0.1"
        dst_ip = data_info.get("dstip") or alert_data.get("dstip") or "172.16.10.10"
        timestamp = alert_data.get("@timestamp") or alert_data.get("timestamp") or "2026-09-07T16:00:00Z"
        agent_name = agent_info.get("name", "Unknown-Agent")

        correlation_required = rule_level >= 10
        correlated_results = None
        fallback_message = "Không ghi nhận hoạt động tương quan nào từ IP này trên các thiết bị khác trong khoảng thời gian +/- 15 phút."

        if correlation_required:
            print(f"⚡ [Incident Assistant] Alert Level {rule_level} >= 10. Executing search_correlated_events for IP: {src_ip}")
            correlated_results = self.correlation_tool.search_correlated_events(
                target_ip=src_ip,
                base_timestamp=timestamp,
                time_window_minutes=15
            )

        # Build SOC Incident Briefing Report
        report_sections = []
        report_sections.append(f"## 🛡️ Báo Cáo Tri-age Sự Cố An Ninh Mạng (SOC Incident Briefing)")
        report_sections.append(f"- **Mức độ rủi ro**: Level {rule_level} ({'CRITICAL/HIGH' if rule_level >= 10 else 'NORMAL'})")
        report_sections.append(f"- **Mã Cảnh Báo (Rule ID)**: `{rule_id}` - {rule_desc}")
        report_sections.append(f"- **Thiết Bị Ghi Nhận**: `{agent_name}` (IP Nguồn: `{src_ip}` ➔ IP Đích: `{dst_ip}`)")
        report_sections.append(f"- **Thời Gian Tương Ứng**: `{timestamp}`")
        report_sections.append("")

        if correlation_required:
            report_sections.append("### 🔗 Phân Tích Tương Quan Đa Thiết Bị (Cross-Device Activity)")
            
            if isinstance(correlated_results, list) and len(correlated_results) > 0:
                flow_diagram = self.build_attack_flow_diagram(src_ip, correlated_results)
                report_sections.append(f"**Sơ Đồ Luồng Tấn Công Quá Mạng (Attack Flow):**")
                report_sections.append(f"```text\n{flow_diagram}\n```")
                report_sections.append("")
                report_sections.append(f"**Danh Sách Sự Kiện Tương Quan Trên Hạ Tầng (Correlated Events):**")
                report_sections.append("| Thời Gian (Timestamp) | Thiết Bị (Agent) | Rule ID | Level | Mô Tả Chi Tiết | IP Nguồn | IP Đích |")
                report_sections.append("|---|---|---|---|---|---|---|")
                
                for ev in correlated_results:
                    report_sections.append(
                        f"| `{ev.get('timestamp')}` | `{ev.get('agent.name')}` | `{ev.get('rule.id')}` | Level {ev.get('rule.level', 0)} | {ev.get('rule.description')} | `{ev.get('srcip')}` | `{ev.get('dstip')}` |"
                    )
            else:
                report_sections.append(fallback_message)
        else:
            report_sections.append("### ℹ️ Thông Tin Mở Rộng")
            report_sections.append("Alert này thuộc mức rủi ro bình thường (Level < 10), không kích hoạt truy vấn tương quan đa thiết bị tự động.")

        full_report = "\n".join(report_sections)
        return {
            "success": True,
            "rule_level": rule_level,
            "correlation_triggered": correlation_required,
            "target_ip": src_ip,
            "correlated_events": correlated_results if isinstance(correlated_results, list) else [],
            "briefing_report": full_report
        }
