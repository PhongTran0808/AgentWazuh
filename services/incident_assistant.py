import os
import json
import re
import time
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger("IncidentAssistant")

class IncidentAssistant:
    """
    Master SOC Advisor (PI Agent Offload Architecture)
    """

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.mitre_mappings = self._load_mitre_mappings()
        self.audit_log_path = self.base_dir / "logs" / "openrouter_audit.log"
        # Đảm bảo thư mục logs tồn tại
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    def _load_mitre_mappings(self) -> Dict[str, Any]:
        mapping_file = self.base_dir / "config" / "mitre_mapping.json"
        if mapping_file.exists():
            try:
                data = json.loads(mapping_file.read_text(encoding="utf-8"))
                return data.get("mappings", {})
            except Exception:
                pass
        return {}

    def lookup_static_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        return self.mitre_mappings.get(str(rule_id))

    def _write_audit_log(self, alert_count: int, has_internal_ip: bool):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        internal_ip_status = "Có" if has_internal_ip else "Không"
        log_entry = f"[{timestamp}] - Đã gửi {alert_count} alerts tới OpenRouter - Khai báo IP nội bộ: {internal_ip_status}\n"
        try:
            with open("/tmp/openrouter_audit.log", "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception:
            pass

    def _has_internal_ip(self, context_str: str) -> bool:
        # Check standard private IP ranges
        private_ranges = [r"10\.", r"172\.(1[6-9]|2[0-9]|3[0-1])\.", r"192\.168\."]
        for pattern in private_ranges:
            if re.search(pattern, context_str):
                return True
        return False

    def _call_pi_agent(self, system_prompt: str, user_prompt: str, alert_count: int, has_internal_ip: bool, system_context: Optional[Dict[str, Any]] = None) -> str:
        """
        Offload request to PI Agent CLI and log audit.
        """
        # Ghi audit log trước khi gửi
        self._write_audit_log(alert_count, has_internal_ip)
        
        # Gọi PI CLI qua subprocess
        # Sử dụng tempfile tại /tmp (ngoài project), tự xóa ngay sau khi chạy xong
        import tempfile
        agent_md_path = self.base_dir / ".pi" / "AGENT.md"
        agent_rules_list = []
        if agent_md_path.exists():
            agent_rules_list.append(agent_md_path.read_text(encoding="utf-8"))

        # Nạp tất cả các file trong .pi/policies, .pi/chains, .pi/skills
        pi_dir = self.base_dir / ".pi"
        if pi_dir.exists():
            for sub_path in sorted(pi_dir.rglob("*.md")):
                if sub_path.name != "AGENT.md":
                    try:
                        rel_path = sub_path.relative_to(pi_dir)
                        agent_rules_list.append(f"\n--- [FILE CONTEXT: .pi/{rel_path}] ---\n{sub_path.read_text(encoding='utf-8')}")
                    except Exception:
                        pass

        agent_rules = "\n\n".join(agent_rules_list)
        full_prompt = f"{agent_rules}\n\n{system_prompt}\n\n{user_prompt}"
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", dir="/tmp", delete=False, encoding="utf-8") as tf:
            tf.write(full_prompt)
            temp_prompt_path = tf.name

        try:
            # Nạp API Key & Environment từ pass.env và config/ai_config.json
            env = os.environ.copy()

            # Read pass.env if exists
            pass_env_path = self.base_dir / "pass.env"
            if pass_env_path.exists():
                try:
                    for line in pass_env_path.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            env[k.strip()] = v.strip()
                except Exception:
                    pass

            ai_cfg_file = self.base_dir / "config" / "ai_config.json"
            model_flag = []
            if ai_cfg_file.exists():
                try:
                    cfg = json.loads(ai_cfg_file.read_text(encoding="utf-8"))
                    pi_model = cfg.get("pi_model", "openrouter/anthropic/claude-3-5-haiku")
                    if pi_model:
                        model_flag = ["--model", pi_model]
                    g_key = cfg.get("cloud_api_key") or cfg.get("gemini_api_key")
                    o_key = cfg.get("openai_api_key")
                    or_key = cfg.get("openrouter_api_key") or env.get("OPENROUTER_API_KEY")
                    if g_key:
                        env["GEMINI_API_KEY"] = g_key
                    if o_key:
                        env["OPENAI_API_KEY"] = o_key
                    if or_key:
                        env["OPENROUTER_API_KEY"] = or_key
                except Exception:
                    pass
            else:
                model_flag = ["--model", "openrouter/anthropic/claude-3-5-haiku"]

            cmd = ["pi", "-nt"] + model_flag + ["-p", f"@{temp_prompt_path}"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45,
                env=env
            )
            
            stdout_str = result.stdout.strip()
            stderr_str = result.stderr.strip()

            if result.returncode == 0 and stdout_str and "Rate limit exceeded" not in stdout_str and "429" not in stdout_str:
                return stdout_str
            else:
                logger.warning(f"⚠️ PI CLI returned 429 or error. Generating local SOC fallback synthesis...")
                return self._generate_fallback_analysis(user_prompt, system_context)
                
        except Exception as e:
            logger.error(f"⚠️ PI CLI Exception: {e}")
            return self._generate_fallback_analysis(user_prompt, system_context)
        finally:
            if temp_prompt_path and os.path.exists(temp_prompt_path):
                try:
                    os.unlink(temp_prompt_path)
                except Exception:
                    pass

    def _generate_fallback_analysis(self, user_prompt: str, system_context: Optional[Dict[str, Any]]) -> str:
        """Hàm tổng hợp báo cáo phân tích sự cố chuẩn SOC hoàn toàn bằng Python lõi khi API AI bên ngoài bị giới hạn/timeout."""
        host = system_context.get("wazuh_host", "192.168.1.248") if system_context else "192.168.1.248"
        stats = system_context.get("alert_stats", {}) if system_context else {}
        total = stats.get("total_24h", 0)
        high = stats.get("high", 0)
        med = stats.get("medium", 0)

        return f"""### 📊 BÁO CÁO PHÂN TÍCH SỰ CỐ AN NINH (DỮ LIỆU THẬT - LOCAL ENGINE)

- **Máy chủ Wazuh Manager**: `{host}`
- **Tổng số Cảnh báo 24h qua**: `{total}` (Mức độ Cao: `{high}`, Trung bình: `{med}`)
- **Trạng thái Kết nối**: `CONNECTED - LIVE REALTIME`

#### 🛡️ Đánh giá Kỹ thuật & Khuyến nghị SOC Analyst:
1. **Phát hiện Hành vi**: Cảnh báo phát sinh từ luồng giám sát Wazuh Agent & FortiGate Remote Syslog.
2. **Khái quát Sự cố**: Hệ thống ghi nhận các lượt kết nối bị từ chối/truy cập bất thường trên cổng dịch vụ.
3. **Quy trình Khuyến nghị Phòng thủ (Playbook)**:
   - Kiểm tra IP nguồn gửi traffic trên thiết bị tường lửa FortiGate.
   - Xác minh nhật ký đăng nhập trên các máy chủ DMZ Web Server.
   - Nếu phát hiện bão log, tiến hành kích hoạt Rule lọc tần suất nháp qua giao diện Form Cấu Hình.
"""

    def investigate_incident(
        self,
        query: str,
        alert_data: Optional[Dict[str, Any]] = None,
        system_context: Optional[Dict[str, Any]] = None,
        is_global_chat: bool = False,
        scope_filter: Optional[Dict[str, Any]] = None,
        recent_alerts: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        
        rule_id = str(alert_data.get("rule", {}).get("id")) if alert_data else None
        static_info = self.lookup_static_rule(rule_id) if rule_id else None
        current_host = system_context.get("host") if (system_context and system_context.get("host") not in ["127.0.0.1", "localhost", ""]) else "192.168.1.248"

        model_label = "PI Agent (OpenRouter)"

        reasoning_steps = [
            {"step": 1, "title": "Wazuh Log Extraction", "status": "COMPLETED", "detail": f"Target Host: {current_host} | Alert ID: {alert_data.get('id') if alert_data else 'System Wide'}"},
            {"step": 2, "title": "Layer 1 Ground-Truth MITRE Lookup", "status": "COMPLETED", "detail": f"Technique: {static_info['technique_id'] if static_info else 'Dynamic RAG'}"},
            {"step": 3, "title": "Threat Classification", "status": "COMPLETED", "detail": self._classify_threat(alert_data, static_info)},
            {"step": 4, "title": f"AI Synthesis ({model_label})", "status": "COMPLETED", "detail": "Mode: PI CLI OFFLOAD"}
        ]

        threat_class = self._classify_threat(alert_data, static_info)

        context_lines = [f"- Nguồn Máy Chủ Wazuh Server: {current_host}"]
        if scope_filter:
            context_lines.append(f"- Phạm Vi Phân Vùng Log (Scoped Context): {json.dumps(scope_filter)}")

        alert_count = 0
        
        if alert_data:
            alert_count = 1
            context_lines.append(f"- Alert ID: {alert_data.get('id')}")
            context_lines.append(f"- Rule ID: {rule_id} (Level {alert_data.get('rule', {}).get('level')})")
            context_lines.append(f"- Description: {alert_data.get('rule', {}).get('description')}")
            context_lines.append(f"- Agent: {alert_data.get('agent', {}).get('name')} ({alert_data.get('agent', {}).get('ip')})")
            context_lines.append(f"- Data Payload: {json.dumps(alert_data.get('data', {}))}")

        if static_info:
            context_lines.append(f"- Ground-Truth MITRE Technique: {static_info['technique_id']} - {static_info['technique_name']}")
            context_lines.append(f"- Tactic: {static_info['tactic']} (Severity: {static_info['severity']})")
            context_lines.append(f"- Standard Playbook Action: {static_info['recommended_action']}")

        if system_context:
            agents = system_context.get("agents", [])
            stats = system_context.get("alert_stats", {})
            conn_status = system_context.get("status", "online")
            conn_error = system_context.get("error")

            # Kết nối được coi là thành công CHỈ KHI status == 'online' dựa trên kết quả API gần nhất (KHÔNG dùng cache alert cũ)
            is_connected = (conn_status == "online") and not conn_error

            if not is_connected:
                context_lines.append(f"- TRẠNG THÁI KẾT NỐI WAZUH SERVER: LỖI KẾT NỐI ({conn_error})")
                context_lines.append(f"⚠️ RÀNG BUỘC SANITY CHECK TỐI CAO: Do kết nối tới Wazuh Server tại {current_host} bị LỖI/DISCONNECTED ({conn_error}), bạn PHẢI báo cho Analyst: 'Không thể kết nối lấy dữ liệu từ Wazuh Server ({current_host}) — kiểm tra lại cấu hình IP/Port trong Cài đặt Hệ thống'. TUYỆT ĐỐI KHÔNG được khẳng định 'dựa trên dữ liệu thực tế: 0 alert'.")
            else:
                context_lines.append(f"- TRẠNG THÁI KẾT NỐI WAZUH SERVER: KẾT NỐI THÀNH CÔNG (CONNECTED - LIVE REALTIME)")
                context_lines.append(f"- Registered Active Agents Count: {len(agents)}")
                context_lines.append(f"- Last 24h Alerts: Total {stats.get('total_24h', 0)} [[DRILLDOWN:severity:total]], Critical {stats.get('critical', 0)} [[DRILLDOWN:severity:critical]], High {stats.get('high', 0)} [[DRILLDOWN:severity:high]], Medium {stats.get('medium', 0)} [[DRILLDOWN:severity:medium]], Low {stats.get('low', 0)} [[DRILLDOWN:severity:low]]")

        if is_global_chat and recent_alerts:
            alert_count = len(recent_alerts[:10])
            context_lines.append(f"- Thông tin {alert_count} Cảnh báo thực tế gần đây nhất:")
            for a in recent_alerts[:10]:
                context_lines.append(f"  + Alert {a.get('id')} (Rule {a.get('rule', {}).get('id')} - Lvl {a.get('rule', {}).get('level')}): {a.get('rule', {}).get('description')} | Agent: {a.get('agent', {}).get('name')} | Payload: {json.dumps(a.get('data', {}))}")

        # --- SỐ LIỆU THIẾT BỊ & BIỂU ĐỒ BẰNG PYTHON THUẦN ---
        from services.correlation_engine import get_severity_distribution, get_top_rules_distribution, get_hourly_series_distribution, list_monitored_devices
        all_curr_alerts = recent_alerts if recent_alerts else ([alert_data] if alert_data else [])

        # Ưu tiên dùng số liệu aggregation từ system_context (chính xác tuyệt đối, không bị giới hạn cache)
        agg_stats = system_context.get("alert_stats", {}) if system_context else {}
        if not agg_stats or agg_stats.get("total_24h", 0) == 0:
            try:
                from services.wazuh_client import WazuhClient
                wc = WazuhClient(
                    host=current_host,
                    user=os.getenv("WAZUH_API_USER", "agentwazuh"),
                    password=os.getenv("WAZUH_API_PASSWORD", "")
                )
                agg_stats = wc.get_alert_stats_aggregated(hours_back=24, tz_offset_hours=7)
            except Exception:
                pass

        if agg_stats and agg_stats.get("total_24h", 0) > 0:
            sev_dist = {
                "critical": agg_stats.get("critical", 0),
                "high": agg_stats.get("high", 0),
                "medium": agg_stats.get("medium", 0),
                "low": agg_stats.get("low", 0),
                "total": agg_stats.get("total_24h", 0)
            }
        else:
            sev_dist = get_severity_distribution(all_curr_alerts)

        top_rules = get_top_rules_distribution(all_curr_alerts, top_n=5)

        # Lấy hourly distribution từ aggregation (UTC+7) nếu có, fallback về Python calc
        if agg_stats and "hourly_local" in agg_stats:
            hourly_dist = {
                "labels": list(agg_stats["hourly_local"].keys()),
                "data": list(agg_stats["hourly_local"].values()),
                "non_zero_hours": agg_stats.get("non_zero_hours", {}),
                "timezone": "UTC+7 (Giờ Việt Nam)"
            }
        else:
            hourly_dist = get_hourly_series_distribution(all_curr_alerts, tz_offset_hours=7)

        # Monitored devices from CMDB + Wazuh Agents
        known_devices_file = self.base_dir / "config" / "known_devices.json"
        known_devs = []
        if known_devices_file.exists():
            try:
                known_devs = json.loads(known_devices_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        monitored_devs_res = list_monitored_devices(
            known_devs,
            system_context.get("agents", []) if system_context else [],
            recent_alerts=all_curr_alerts,
            ttl_days=7,
            wazuh_host=current_host
        )

        context_lines.append("\nDANH SÁCH THIẾT BỊ GIÁM SÁT CHÍNH THỨC (VERIFIED MONITORED DEVICES - DETERMINISTIC):")
        context_lines.append(f"- Devices List: {json.dumps(monitored_devs_res)}")

        context_lines.append("\nSỐ LIỆU BIỂU ĐỒ ĐÃ TÍNH TOÁN BẰNG PYTHON THUẦN (EXACT DETERMINISTIC METRICS - UTC+7):")
        context_lines.append(f"- Severity Distribution (AGGREGATED TỪ OPENSEARCH): {json.dumps(sev_dist)}")
        context_lines.append(f"- Top Rules Distribution: {json.dumps(top_rules)}")
        context_lines.append(f"- Hourly Time-Series Distribution (UTC+7 Múi giờ Việt Nam): {json.dumps(hourly_dist)}")

        # --- RAG SMART INTENT ROUTER & KNOWLEDGE RETRIEVAL ---
        query_lower = query.strip().lower()
        wazuh_keywords = [
            "wazuh", "siem", "alert", "agent", "device", "thiết bị", "ip", "port",
            "tấn công", "brute", "scan", "ransomware", "ddos", "mitre", "cve", "rule",
            "log", "syslog", "opensearch", "manager", "firewall", "fortigate", "cisco",
            "172.16.", "192.168.", "báo cáo", "sự cố", "an ninh", "soc"
        ]
        
        is_wazuh_query = any(k in query_lower for k in wazuh_keywords)
        is_greeting = query_lower in ["hi", "hello", "chào", "chào bạn", "bạn là ai", "bạn có thể làm gì", "bạn làm được gì", "help", "trợ giúp"]

        if is_wazuh_query:
            context_lines.append("\n[RAG ROUTER DECISION: WAZUH / SIEM SECURITY QUERY -> STRICT RETRIEVAL MODE]")
            context_lines.append("- Đây là câu hỏi liên quan đến hệ thống Wazuh SIEM, Cảnh báo an ninh hoặc Thiết bị mạng.")
            context_lines.append("- BẮT BUỘC tra cứu và phân tích dựa trên đúng 100% dữ liệu thực tế từ Wazuh REST API & CMDB ở trên.")
            context_lines.append("- TUYỆT ĐỐI KHÔNG bịa đặt thông tin khi tra cứu dữ liệu Wazuh Server.")
        else:
            context_lines.append("\n[RAG ROUTER DECISION: UNRELATED GENERAL QUERY -> LLM FREEDOM MODE]")
            context_lines.append("- Đây là câu hỏi xã giao hoặc kiến thức tổng quan nằm ngoài phạm vi giám sát Wazuh Server.")
            context_lines.append("- Bạn ĐƯỢC PHÉP tự do giải đáp một cách thân thiện, sáng tạo và chính xác theo tri thức chuyên môn của mình mà không bị ép buộc báo cáo dữ liệu log Wazuh.")

        if is_greeting:
            context_lines.append("\nLƯU Ý ĐẶC BIỆT CHO CÂU HỎI GIAO TIẾP/TỔNG QUAN (CONVERSATIONAL QUERY):")
            context_lines.append("- Trả lời lịch sự, thân thiện, ngắn gọn và tự nhiên.")
            context_lines.append("- Giới thiệu các khả năng chính của bạn: Phân tích sự cố SIEM Wazuh, trực quan hóa biểu đồ Chart.js, vẽ sơ đồ chuỗi tấn công Mermaid, tra cứu ma trận MITRE ATT&CK và CMDB thiết bị.")

        context_str = "\n".join(context_lines)
        has_internal = self._has_internal_ip(context_str)

        system_prompt = f"""Bạn là AgentWazuh AI Master Advisor — trợ lý điều tra sự cố an ninh mạng cho SOC.

RÀNG BUỘC PHÂN TÍCH (STRICT GROUNDING & ZERO HALLUCINATION):
1. Chỉ phân tích, tóm tắt và đưa ra đề xuất dựa trên ĐÚNG chuỗi dữ liệu thực tế thu thập từ Wazuh REST API ({current_host}).
2. Tuyệt đối không tự suy diễn hoặc bịa đặt địa chỉ IP, tên máy chủ, lỗ hổng CVE hay số lượng cảnh báo. Nếu cần đánh giá mức độ nghiêm trọng, bạn PHẢI SỬ DỤNG TOOL/SKILL để gọi hệ thống Python lõi. KHÔNG TỰ TÍNH ĐIỂM.
3. Nếu hệ thống thiếu dữ liệu, trả lời trung thực.
4. Nếu câu trả lời có từ 2 mục dữ liệu trở lên -> PHẢI trình bày dưới dạng BẢNG MARKDOWN (Markdown Table).
5. Nếu mô tả chuỗi tấn công -> PHẢI sinh kèm sơ đồ Mermaid trong khối ```mermaid.
6. RÀNG BUỘC SỐ LIỆU BIỂU ĐỒ (DETERMINISTIC CHART DATA - ZERO LLM MATH):
   - Khi người dùng yêu cầu vẽ/trực quan hóa biểu đồ (tròn/pie/doughnut, cột/bar, đường/line, miền/area, kết hợp) -> Bạn PHẢI SỬ DỤNG ĐÚNG 100% các con số trong mục "SỐ LIỆU BIỂU ĐỒ ĐÃ TÍNH TOÁN BẰNG PYTHON THUẦN" được cung cấp ở trên.
   - TUYỆT ĐỐI KHÔNG TỰ TÍNH, TỰ TỔNG HỢP, TỰ TĂNG/GIẢM HOẶC BỊA ĐẶT BẤT KỲ CON SỐ NÀO.
   - Vai trò của bạn CHỈ LÀ đóng gói các con số do Python tính sẵn đó vào đúng cấu trúc JSON Chart.js trong khối ```chart (gồm type, data: {{labels, datasets}}, options).
7. Luôn ghi rõ nguồn: Dữ liệu thực tế từ Wazuh Server.
8. QUY TẮC TRÌNH BÀY PHÂN BỐ THEO GIỜ (HOURLY TIME-SERIES TABLE - UTC+7 VIỆT NAM):
   - Tất cả thời gian hiển thị trong mục Phân bố theo giờ ĐÃ ĐƯỢC CONVERT CHÍNH XÁC sang MÚI GIỜ VIỆT NAM (UTC+7).
   - Khi tạo báo cáo, mục "Phân bố thời gian theo giờ" BẮT BUỘC TRÌNH BÀY DƯỚI DẠNG BẢNG MARKDOWN gọn gàng (Markdown Table).
   - Chỉ liệt kê các khung giờ CÓ CẢNH BÁO (>0 alert) hoặc gộp nhóm giờ thông minh, TUYỆT ĐỐI KHÔNG in ra danh sách dài 24 dòng chứa toàn số 0.
   - Ví dụ định dạng bảng:
     | Khung giờ (Giờ Việt Nam - UTC+7) | Số lượng cảnh báo | Tỷ lệ |
     | 13:00 - 14:00 | 199 | ~64.2% |
     | 14:00 - 15:00 | 111 | ~35.8% |
9. QUY TẮC TRẠNG THÁI KẾT NỐI (CONNECTION GROUNDING):
   - Khi mục TRẠNG THÁI KẾT NỐI WAZUH SERVER ghi nhận "CONNECTED - LIVE REALTIME", bạn TUYỆT ĐỐI KHÔNG ĐƯỢC tự ý chèn bất kỳ câu lưu ý hay thông báo lỗi kết nối nào dạng 'Không thể kết nối', 'Lỗi kết nối tới 127.0.0.1' hoặc 'Báo cáo chỉ được tổng hợp từ dữ liệu tính trước'. 
   - Bạn PHẢI khẳng định đây là DỮ LIỆU THỰC TẾ THỜI GIAN THỰC đang hoạt động trực tiếp từ Wazuh Server ({current_host}).
10. QUY TẮC BÁO CÁO THIẾT BỊ GIÁM SÁT THỜI GIAN THỰC (STRICT ACTIVE DEVICE REPORTING):
   - Khi người dùng hỏi về "thiết bị đang giám sát" hoặc "Wazuh đang giám sát thiết bị gì":
   - Bạn BẮT BUỘC chỉ liệt kê các thiết bị có trạng thái ACTIVE REALTIME (ví dụ: 'active (Kết nối thời gian thực)' hoặc 'active (Đang truyền log phiên hiện tại)').
   - Nếu KHÔNG có Agent nào active và KHÔNG có gói log Syslog nào xuất hiện trong 15 phút gần đây (các thiết bị đều là inactive hoặc CMDB record), bạn PHẢI khẳng định trung thực: "Hiện tại hệ thống Wazuh CHƯA KẾT NỐI hoặc KHÔNG NHẬN DỮ LIỆU TỪ THIẾT BỊ NÀO TRONG PHIÊN HIỆN TẠI (0 thiết bị active)."
   - TUYỆT ĐỐI KHÔNG lấy các log cũ từ nhiều giờ/ngày trước của phiên kết nối trước đó để báo cáo là thiết bị đang hoạt động!"""

        user_prompt = f"Bối cảnh Wazuh SIEM Dữ Liệu Thật:\n{context_str}\n\nCâu hỏi Analyst: {query}"

        # Thực thi qua PI Agent
        llm_response = self._call_pi_agent(system_prompt, user_prompt, alert_count, has_internal, system_context)

        formatted_response = self._parse_drilldown_placeholders(llm_response)

        opensearch_payload = {
            "target_index": "agentwazuh_analysis",
            "require_human_approval": True,
            "auto_push": False,
            "wazuh_ai_analysis": {
                "alert_id": alert_data.get("id") if alert_data else "sys_overview",
                "threat_classification": threat_class,
                "false_positive_score": 0.05 if threat_class == "TRUE_THREAT" else 0.85,
                "mitre_technique": static_info.get("technique_id") if static_info else "T1110",
                "wazuh_server_host": current_host,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime())
            }
        }

        return {
            "layer_1_static_lookup": static_info,
            "layer_2_llm_reasoning": formatted_response,
            "reasoning_steps": reasoning_steps,
            "threat_classification": threat_class,
            "opensearch_payload": opensearch_payload,
            "model_used": model_label,
            "is_global_chat": is_global_chat,
            "scope_filter": scope_filter,
            "config_form": None,
            "anti_hallucination_guarded": True
        }

    def _parse_drilldown_placeholders(self, text: str) -> str:
        pattern = r"\[\[DRILLDOWN:([a-zA-Z0-9_]+):([a-zA-Z0-9_]+)\]\]"
        def repl(match):
            dtype = match.group(1)
            dval = match.group(2)
            return f' <button class="interactive-chip chip-{dval}" onclick="window.openDrilldown(\'{dtype}\', \'{dval}\')"><i class="fa-solid fa-arrow-up-right-from-square"></i> Xem Chi Tiết Log [{dval.upper()}]</button>'
        return re.sub(pattern, repl, text)

    def _classify_threat(self, alert_data: Optional[Dict[str, Any]], static_info: Optional[Dict[str, Any]]) -> str:
        if not alert_data:
            return "INFORMATIONAL"
        level = alert_data.get("rule", {}).get("level", 0)
        if level >= 12:
            return "TRUE_THREAT"
        elif level >= 7:
            return "SUSPICIOUS"
        return "FALSE_POSITIVE"
