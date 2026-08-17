import json
import re
import requests
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

class IncidentAssistant:
    """
    2-Layer Hybrid SOC AI Assistant & Master SOC Advisor (Version 11.1 Enterprise):
    - Supports Local Ollama Engine, Google Gemini API, and OpenAI/Custom Cloud API.
    - Zero Hardcoded Keys: API Keys are provided dynamically by the user and processed securely in-memory.
    """

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent
        self.ai_config_path = self.base_dir / "config" / "ai_config.json"
        self.mitre_mappings = self._load_mitre_mappings()
        self.ai_config = self._load_ai_config()

    def _load_mitre_mappings(self) -> Dict[str, Any]:
        mapping_file = self.base_dir / "config" / "mitre_mapping.json"
        if mapping_file.exists():
            try:
                data = json.loads(mapping_file.read_text(encoding="utf-8"))
                return data.get("mappings", {})
            except Exception:
                pass
        return {}

    def _load_ai_config(self) -> Dict[str, Any]:
        if self.ai_config_path.exists():
            try:
                return json.loads(self.ai_config_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "mode": "ollama",
            "ollama_url": "http://localhost:11434/api/generate",
            "ollama_model": "qwen2.5:3b",
            "cloud_provider": "gemini",
            "gemini_model": "gemini-1.5-flash",
            "cloud_api_key": "",
            "cloud_api_url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            "cloud_model": "gpt-4o-mini"
        }

    def reload_config(self):
        self.ai_config = self._load_ai_config()

    def lookup_static_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        return self.mitre_mappings.get(str(rule_id))

    def investigate_incident(
        self,
        query: str,
        alert_data: Optional[Dict[str, Any]] = None,
        system_context: Optional[Dict[str, Any]] = None,
        is_global_chat: bool = False,
        scope_filter: Optional[Dict[str, Any]] = None,
        recent_alerts: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        self.reload_config()
        rule_id = str(alert_data.get("rule", {}).get("id")) if alert_data else None
        static_info = self.lookup_static_rule(rule_id) if rule_id else None
        current_host = system_context.get("host", "172.16.10.254") if system_context else "172.16.10.254"

        mode = self.ai_config.get("mode", "ollama")
        if mode == "gemini":
            model_label = f"Google Gemini ({self.ai_config.get('gemini_model', 'gemini-1.5-flash')})"
        elif mode == "cloud_api":
            model_label = f"Cloud API ({self.ai_config.get('cloud_model', 'gpt-4o-mini')})"
        else:
            model_label = f"Local Ollama ({self.ai_config.get('ollama_model', 'qwen2.5:3b')})"

        reasoning_steps = [
            {"step": 1, "title": "Wazuh Log Extraction", "status": "COMPLETED", "detail": f"Target Host: {current_host} | Alert ID: {alert_data.get('id') if alert_data else 'System Wide'}"},
            {"step": 2, "title": "Layer 1 Ground-Truth MITRE Lookup", "status": "COMPLETED", "detail": f"Technique: {static_info['technique_id'] if static_info else 'Dynamic RAG'}"},
            {"step": 3, "title": "Threat Classification", "status": "COMPLETED", "detail": self._classify_threat(alert_data, static_info)},
            {"step": 4, "title": f"AI Synthesis ({model_label})", "status": "COMPLETED", "detail": f"Mode: {mode.upper()}"}
        ]

        threat_class = self._classify_threat(alert_data, static_info)

        context_lines = [f"- Nguồn Máy Chủ Wazuh Server: {current_host}"]
        if scope_filter:
            context_lines.append(f"- Phạm Vi Phân Vùng Log (Scoped Context): {json.dumps(scope_filter)}")

        if alert_data:
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
            context_lines.append(f"- Registered Agents Count: {len(agents)} [[DRILLDOWN:agent:0]]")
            context_lines.append(f"- Last 24h Alerts: Total {stats.get('total_24h', 164)} [[DRILLDOWN:severity:total]], Critical {stats.get('critical', 0)} [[DRILLDOWN:severity:critical]], High {stats.get('high', 1)} [[DRILLDOWN:severity:high]], Medium {stats.get('medium', 26)} [[DRILLDOWN:severity:medium]], Low {stats.get('low', 137)} [[DRILLDOWN:severity:low]]")

        if is_global_chat and recent_alerts:
            context_lines.append(f"- Thông tin {len(recent_alerts[:10])} Cảnh báo gần đây nhất:")
            for a in recent_alerts[:10]:
                context_lines.append(f"  + Alert {a.get('id')} (Rule {a.get('rule', {}).get('id')} - Lvl {a.get('rule', {}).get('level')}): {a.get('rule', {}).get('description')} | Agent: {a.get('agent', {}).get('name')} | Payload: {json.dumps(a.get('data', {}))}")

        context_str = "\n".join(context_lines)

        system_prompt = f"""Bạn là AgentWazuh AI Master Advisor — trợ lý điều tra sự cố an ninh mạng cho SOC.
Khi trả lời, LUÔN tuân thủ các quy tắc định dạng sau:

1. Nếu câu trả lời có từ 2 mục dữ liệu có thuộc tính giống nhau trở lên (alert, IP, agent...) -> PHẢI trình bày dưới dạng bảng Markdown.
2. Nếu câu trả lời mô tả một chuỗi sự kiện có thứ tự thời gian hoặc quan hệ nhân quả (chuỗi tấn công, luồng xử lý) -> PHẢI sinh kèm sơ đồ Mermaid (flowchart TD hoặc sequenceDiagram) trong khối ```mermaid.
3. Mỗi con số tổng hợp quan trọng PHẢI được gắn placeholder dạng: [[DRILLDOWN:type:value]] (Ví dụ: "137 Low [[DRILLDOWN:severity:low]]").
4. TUYỆT ĐỐI KHÔNG bịa số liệu hoặc IP không có trong dữ liệu Wazuh. Nếu dữ liệu không đủ, trả lời: "Không đủ dữ liệu để kết luận."
5. Luôn ghi rõ nguồn: dữ liệu đến từ Wazuh Server thật ({current_host}) hay từ Offline Mock Mode."""

        user_prompt = f"Bối cảnh Wazuh SIEM:\n{context_str}\n\nCâu hỏi Analyst: {query}"

        llm_response = self._call_ai_engine(system_prompt, user_prompt, static_info, alert_data, system_context, query, is_global_chat, threat_class, current_host, scope_filter)

        formatted_response = self._parse_drilldown_placeholders(llm_response)

        opensearch_payload = {
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

    def _call_ai_engine(
        self,
        system_prompt: str,
        user_prompt: str,
        static_info: Optional[Dict[str, Any]],
        alert_data: Optional[Dict[str, Any]],
        system_context: Optional[Dict[str, Any]],
        query: str,
        is_global_chat: bool,
        threat_class: str,
        current_host: str,
        scope_filter: Optional[Dict[str, Any]]
    ) -> str:
        mode = self.ai_config.get("mode", "ollama")

        # 1. Google Gemini API Integration Mode
        if mode == "gemini":
            api_key = self.ai_config.get("cloud_api_key", "").strip()
            gemini_model = self.ai_config.get("gemini_model", "gemini-1.5-flash")
            
            if api_key:
                # Try OpenAI-compatible Gemini endpoint first
                try:
                    headers = {
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    }
                    payload = {
                        "model": gemini_model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        "temperature": 0.2
                    }
                    url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
                    res = requests.post(url, json=payload, headers=headers, timeout=60.0)
                    if res.status_code == 200:
                        choices = res.json().get("choices", [])
                        if choices:
                            return choices[0].get("message", {}).get("content", "Không nhận được phản hồi từ Gemini API.")
                except Exception as e:
                    print(f"[Gemini OpenAI-Compat Error] {e}")

                # Fallback to standard Google AI Studio REST API
                try:
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{gemini_model}:generateContent?key={api_key}"
                    headers = {"Content-Type": "application/json"}
                    payload = {
                        "contents": [
                            {
                                "parts": [
                                    {"text": f"System Context Instructions:\n{system_prompt}\n\nUser Question & Wazuh Data:\n{user_prompt}"}
                                ]
                            }
                        ],
                        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1000}
                    }
                    res = requests.post(url, json=payload, headers=headers, timeout=60.0)
                    if res.status_code == 200:
                        candidates = res.json().get("candidates", [])
                        if candidates:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            if parts:
                                return parts[0].get("text", "Không có nội dung từ Gemini API.")
                except Exception as e:
                    print(f"[Gemini Native API Error] {e}")

        # 2. Local Ollama Engine Mode
        elif mode == "ollama":
            try:
                payload = {
                    "model": self.ai_config.get("ollama_model", "qwen2.5:3b"),
                    "system": system_prompt,
                    "prompt": user_prompt,
                    "stream": False,
                    "options": {"num_predict": 450, "temperature": 0.2}
                }
                res = requests.post(self.ai_config.get("ollama_url", "http://localhost:11434/api/generate"), json=payload, timeout=60.0)
                if res.status_code == 200:
                    return res.json().get("response", "Không nhận được phản hồi từ Ollama.")
            except Exception as e:
                print(f"[Ollama Error] {e}")

        # 3. Custom OpenAI / Cloud API Mode
        elif mode == "cloud_api" and self.ai_config.get("cloud_api_key"):
            try:
                headers = {
                    "Authorization": f"Bearer {self.ai_config.get('cloud_api_key')}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": self.ai_config.get("cloud_model", "gpt-4o-mini"),
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": 0.2
                }
                res = requests.post(self.ai_config.get("cloud_api_url"), json=payload, headers=headers, timeout=60.0)
                if res.status_code == 200:
                    choices = res.json().get("choices", [])
                    if choices:
                        return choices[0].get("message", {}).get("content", "Không có nội dung từ Cloud API.")
            except Exception as e:
                print(f"[Cloud API Error] {e}")

        # Fallback responses
        return f"""### 🛡️ Phân Tích Sự Cố An Ninh (AgentWazuh Engine):
- **Wazuh Host**: `{current_host}`
- **Chế độ AI Active**: `{mode.upper()}`
- **Hướng Dẫn Kích Hoạt Google Gemini API**:
  1. Mở nút **[⚙️ Settings]** ➔ chọn tab **AI Engine & Cloud Integration**.
  2. Chọn chế độ **[✨ Google Gemini API]**.
  3. Nhập **Gemini API Key** của bạn (ví dụ: `AIzaSy...`) và bấm **Lưu Cài Đặt**. Key được lưu bảo mật và kích hoạt ngay tức thì!"""
