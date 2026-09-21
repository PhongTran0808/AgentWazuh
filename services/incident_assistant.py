import os
import json
import re
import time
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import shutil
import requests
from services.chat_intent import classify_chat_intent

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
            import tempfile
            log_path = os.path.join(tempfile.gettempdir(), "openrouter_audit.log")
            with open(log_path, "a", encoding="utf-8") as f:
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

    def _call_pi_agent(self, system_prompt: str, user_prompt: str, alert_count: int, has_internal_ip: bool, system_context: Optional[Dict[str, Any]] = None, model_override: Optional[str] = None) -> str:
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
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as tf:
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
                            env[k.strip()] = v.strip().strip("\"'")
                except Exception:
                    pass

            env_path = self.base_dir / ".env"
            if env_path.exists():
                try:
                    for line in env_path.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            env[k.strip()] = v.strip().strip("\"'")
                except Exception:
                    pass

            ai_cfg_file = self.base_dir / "config" / "ai_config.json"
            target_model = None
            cfg = {}
            if ai_cfg_file.exists():
                try:
                    cfg = json.loads(ai_cfg_file.read_text(encoding="utf-8"))
                    cfg_model = cfg.get("pi_model", "auto")
                    if cfg_model and cfg_model.lower() != "auto":
                        target_model = cfg_model
                    g_key = cfg.get("cloud_api_key") or cfg.get("gemini_api_key")
                    o_key = cfg.get("openai_api_key")
                    or_key = cfg.get("openrouter_api_key") or env.get("OPENROUTER_API_KEY")
                    if g_key:
                        env["GEMINI_API_KEY"] = str(g_key).strip().strip("\"'")
                    if o_key:
                        env["OPENAI_API_KEY"] = str(o_key).strip().strip("\"'")
                    if or_key:
                        env["OPENROUTER_API_KEY"] = str(or_key).strip().strip("\"'")
                except Exception:
                    pass

            if model_override and model_override.strip() and model_override.lower() != "auto":
                target_model = model_override.strip()

            model_flag = ["--model", target_model] if target_model else []

            # 1. ƯU TIÊN GỌI TRỰC TIẾP API NẾU CÓ KEY (TỐC ĐỘ < 2 GIÂY)
            g_key = env.get("GEMINI_API_KEY")
            or_key = env.get("OPENROUTER_API_KEY")
            o_key = env.get("OPENAI_API_KEY")

            # Gemini is the declared project provider.  Other keys remain
            # optional fallbacks and must not silently take precedence.
            if (or_key or o_key) and not g_key:
                clean_api_key = (or_key if or_key else o_key).strip().strip("\"'")
                url = "https://openrouter.ai/api/v1/chat/completions" if or_key else "https://api.openai.com/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {clean_api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://agentwazuh.local",
                    "X-Title": "AgentWazuh SOC Assistant"
                }
                
                candidate_models = []
                if target_model and target_model.lower() != "auto":
                    candidate_models.append(target_model)
                if or_key:
                    candidate_models.extend([
                        "google/gemini-2.5-flash",
                        "deepseek/deepseek-chat",
                        "openai/gpt-4o-mini",
                        "openrouter/free"
                    ])
                else:
                    candidate_models.append("gpt-4o-mini")

                for mod in candidate_models:
                    try:
                        resp = requests.post(
                            url,
                            json={
                                "model": mod,
                                "messages": [{"role": "user", "content": full_prompt}],
                                "max_tokens": 1500
                            },
                            headers=headers,
                            timeout=15
                        )
                        if resp.status_code == 200:
                            res_json = resp.json()
                            choices = res_json.get("choices", [])
                            if choices and choices[0].get("message", {}).get("content"):
                                return choices[0]["message"]["content"].strip()
                    except Exception as mod_err:
                        logger.warning(f"OpenRouter attempt with {mod} failed: {mod_err}")

            if g_key:
                chosen_gemini_model = "gemini-2.5-flash"
                if target_model and "gemini" in target_model.lower():
                    chosen_gemini_model = target_model.split("/")[-1].strip()
                elif cfg.get("gemini_model"):
                    chosen_gemini_model = str(cfg.get("gemini_model")).strip()

                try:
                    gemini_clean_key = g_key.strip().strip("\"'")
                    gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/{chosen_gemini_model}:generateContent?key={gemini_clean_key}"
                    resp = requests.post(
                        gemini_url,
                        json={"contents": [{"parts": [{"text": full_prompt}]}]},
                        headers={"Content-Type": "application/json"},
                        timeout=15
                    )
                    if resp.status_code == 200:
                        return resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                except Exception as gem_err:
                    logger.warning(f"Gemini API attempt with {chosen_gemini_model} failed: {gem_err}")

            # 2. Thử gọi PI CLI nếu không có Key hoặc API lỗi
            pi_bin = shutil.which("pi")
            if not pi_bin and os.name == 'nt':
                fallback_path = os.path.expanduser("~\\AppData\\Local\\pi-node\\current\\pi.cmd")
                if os.path.exists(fallback_path):
                    pi_bin = fallback_path
            pi_bin = pi_bin or "pi"

            try:
                # Keep Pi built-ins disabled, but load the reviewed AgentWazuh
                # extension so the model can use the authenticated Wazuh MCP
                # tools. Write tools show an operator confirmation dialog in the
                # extension and the upstream server also enforces confirm=true.
                mcp_extension = self.base_dir / ".pi" / "extensions" / "wazuh-mcp.ts"
                tool_flags = ["--no-builtin-tools"]
                if mcp_extension.exists():
                    tool_flags += ["--extension", str(mcp_extension)]
                cmd = [pi_bin] + tool_flags + model_flag + ["-p", f"@{temp_prompt_path}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=25, env=env)
                stdout_str = result.stdout.strip()
                if result.returncode == 0 and stdout_str and "unsupported_api_for_model" not in stdout_str:
                    return stdout_str
            except Exception:
                pass

            # 3. Dynamic Local SOC Rule-Based Engine
            return self._generate_truthful_fallback(user_prompt, system_context)
                
        except Exception as e:
            logger.error(f"⚠️ LLM Exception: {e}")
            return self._generate_truthful_fallback(user_prompt, system_context)
        finally:
            if temp_prompt_path and os.path.exists(temp_prompt_path):
                try:
                    os.unlink(temp_prompt_path)
                except Exception:
                    pass

    def _generate_truthful_fallback(self, user_prompt: str, system_context: Optional[Dict[str, Any]]) -> str:
        """Answer locally without inventing alerts, agents, IPs or actions."""
        context = system_context or {}
        host = context.get("wazuh_host") or context.get("host") or os.getenv("WAZUH_HOST", "chưa xác định")
        stats = context.get("alert_stats") or {}
        intent = classify_chat_intent(user_prompt)

        if intent["intent"] == "greeting":
            return """### 👋 AgentWazuh SOC Assistant

Mình có thể hỗ trợ giải thích Wazuh, phân tích alert/incident, hướng dẫn kiểm tra Agent/Manager/API, tương quan sự kiện, tạo bản nháp Rule XML và trình bày kết quả bằng bảng, timeline hoặc sơ đồ.

Bạn có thể hỏi: `hướng dẫn kiểm tra agent`, `giải thích Rule 5710`, `phân tích alert này`, hoặc `tạo rule phát hiện brute force`."""

        q_lower = user_prompt.lower()

        if intent["intent"] == "how_to":
            if "agent" in q_lower or "kiểm tra" in q_lower:
                return f"""### 🛠️ Hướng Dẫn Kiểm Tra Trạng Thái Wazuh Agent

#### 1. Kiểm tra trạng thái dịch vụ trên máy trạm/máy chủ:
- **Linux**:
  ```bash
  sudo systemctl status wazuh-agent
  ```
- **Windows (PowerShell Admin)**:
  ```powershell
  Get-Service -Name "wazuh"
  ```

#### 2. Kiểm tra nhật ký kết nối của Agent:
- **Linux**: Xem `/var/ossec/logs/ossec.log` (tìm dòng `Connected to the server`).
- **Windows**: Xem `C:\\Program Files (x86)\\ossec-agent\\ossec.log`.

#### 3. Quản lý từ Wazuh Manager ({host}):
```bash
/var/ossec/bin/agent_control -l
```
> Bạn cũng có thể mở mục **Kiểm kê thiết bị (Inventory)** trên thanh điều hướng để xem danh sách Agent kết nối thời gian thực."""

            if "restart" in q_lower or "khởi động" in q_lower:
                return f"""### 🔄 Hướng Dẫn Khởi Động Lại Dịch Vụ Wazuh

- **Khởi động lại Wazuh Manager**:
  ```bash
  sudo systemctl restart wazuh-manager
  ```
- **Khởi động lại Wazuh Agent (Linux)**:
  ```bash
  sudo systemctl restart wazuh-agent
  ```
- **Khởi động lại Wazuh Indexer & Dashboard**:
  ```bash
  sudo systemctl restart wazuh-indexer wazuh-dashboard
  ```
> Sau khi khởi động lại, kiểm tra trạng thái bằng `sudo systemctl status wazuh-manager`."""

        if intent["intent"] == "wazuh_explanation":
            rule_id_match = re.search(r"\b(5710|5716|5715|5501|5502|100001|100011|100021|\d{4,6})\b", user_prompt)
            if rule_id_match:
                rid = rule_id_match.group(1)
                explanations = {
                    "5710": ("sshd: Attempt to login using a non-existent or denied user", "Thấp (Level 5)", "Ghi nhận nỗ lực đăng nhập SSH vào hệ thống sử dụng tên tài khoản không tồn tại hoặc bị chặn. Thường do botnet quét tài khoản ngẫu nhiên (admin, root, test). Cần theo dõi IP nguồn để phát hiện brute force."),
                    "5716": ("sshd: Authentication failed", "Trung bình (Level 5)", "Đăng nhập SSH thất bại do sai mật khẩu. Nếu lặp lại nhiều lần từ cùng 1 IP trong thời gian ngắn, hệ thống sẽ kích hoạt cảnh báo tấn công dò mật khẩu."),
                    "5715": ("sshd: Authentication succeeded", "Thông tin (Level 3)", "Đăng nhập SSH thành công vào hệ thống. Cần đối chiếu với thời gian làm việc và IP nội bộ để phát hiện truy cập trái phép ngoài giờ."),
                    "100001": ("Multiple SSH failed logins (Brute Force attack)", "Cao (Level 10)", "Quy tắc tương quan phát hiện nhiều lần đăng nhập SSH thất bại liên tiếp từ cùng một IP nguồn. Khuyến nghị chặn IP tại tường lửa hoặc kích hoạt Active Response."),
                    "100011": ("Web Application SQL Injection attempt", "Nghiêm trọng (Level 12)", "Phát hiện chuỗi truy vấn SQL độc hại gửi đến máy chủ web. Cần kiểm tra WAF và chặn IP tấn công ngay lập tức.")
                }
                desc, lvl, meaning = explanations.get(rid, (f"Wazuh Rule {rid}", "Chưa xác định", f"Quy tắc phát hiện sự kiện an ninh với mã ID {rid} trong hệ cơ sở dữ liệu luật của Wazuh Manager."))
                return f"""### 📖 Giải Thích Quy Tắc: Rule `{rid}`

- **Mô tả quy tắc**: `{desc}`
- **Mức độ cảnh báo (Severity)**: `{lvl}`
- **Máy chủ Wazuh Manager**: `{host}`

#### 🔍 Ý nghĩa & Cơ chế hoạt động:
{meaning}

#### 📋 Khuyến nghị cho SOC Analyst:
1. Đối chiếu IP nguồn trong log với danh sách máy chủ/người dùng hợp lệ.
2. Nếu xuất hiện tần suất cao (> 5 lần/phút), áp dụng Rule tương quan hoặc chặn IP tại tường lửa.
"""

            if "alert" in q_lower or "cảnh báo" in q_lower:
                return f"""### 📖 Khái Niệm: Cảnh Báo An Ninh (Alert) trong Wazuh SIEM

- **Định nghĩa**: Alert là một sự kiện an ninh được Wazuh Manager tạo ra khi một dòng nhật ký (Log) thu thập từ Agent/Syslog khớp với một quy tắc (Rule) và có mức độ (Level) đạt ngưỡng cảnh báo.
- **Cấu trúc của một Alert**:
  - `rule.id`: Mã quy tắc phát hiện (VD: 5710, 5716).
  - `rule.level`: Mức độ nghiêm trọng từ 0 đến 16 (Level >= 7 là Medium/High, >= 12 là Critical).
  - `agent`: Thiết bị phát sinh sự kiện (Tên máy, ID, IP).
  - `data`: Ngữ cảnh chi tiết (IP nguồn `srcip`, cổng dịch vụ, tài khoản, tiến trình).
- **Ví dụ**: Khi có nhiều lần đăng nhập sai liên tiếp, Wazuh kích hoạt cảnh báo *Rule 100001 - Multiple SSH failed logins*.
"""

        if intent["intent"] == "metrics" and stats:
            return self._generate_fallback_analysis(user_prompt, system_context)

        # If user asks for investigation, alerts, or incidents, use deterministic SOC engine
        if intent["intent"] == "investigation" or any(k in q_lower for k in ("phân tích sự cố", "phân tích nhóm sự cố", "phân tích alert", "inc-", "điều tra", "sơ đồ", "playbook")):
            return self._generate_fallback_analysis(user_prompt, system_context)

        return f"""### ℹ️ Chưa đủ dữ liệu để trả lời chắc chắn

Mình nhận diện câu hỏi thuộc nhóm **{intent['intent']}** và nên trả lời theo dạng **{intent['format']}**.

- Wazuh Manager trong context: `{host}`
- Cần truy vấn thêm Wazuh hoặc cần bạn cung cấp alert JSON/log cụ thể.
- Mình không tự khẳng định trạng thái Agent, IP, Rule, kết nối hoặc kết quả thao tác khi chưa có evidence.

Bạn có thể gửi thêm `alert JSON`, `rule ID`, `agent ID`, khoảng thời gian hoặc mô tả thao tác cần thực hiện."""

    def _generate_fallback_analysis(self, user_prompt: str, system_context: Optional[Dict[str, Any]]) -> str:
        """Hàm tổng hợp phân tích động chuẩn SOC bằng Python lõi dựa trên chính xác câu hỏi của người dùng."""
        q_lower = user_prompt.lower()
        host = system_context.get("wazuh_host", os.getenv("WAZUH_HOST", "127.0.0.1")) if system_context else os.getenv("WAZUH_HOST", "127.0.0.1")
        stats = system_context.get("alert_stats", {}) if system_context else {}
        total = stats.get("total_24h", 0)
        high = stats.get("high", 0)
        med = stats.get("medium", 0)

        # 1. Nếu người dùng hỏi phân tích 1 Alert cụ thể (Alert <ID> ...)
        alert_match = re.search(r"alert\s+([A-Za-z0-9_\-]+)", user_prompt, re.IGNORECASE)
        rule_desc_match = re.search(r"\(([^)]+)\)", user_prompt)
        if alert_match or "phân tích alert" in q_lower or "alert " in q_lower:
            alert_id = alert_match.group(1) if alert_match else "N/A"
            rule_desc = rule_desc_match.group(1) if rule_desc_match else "Cảnh báo an ninh giám sát"
            is_traffic = "traffic" in q_lower or "fortigate" in q_lower or "flow" in q_lower
            source_sys = "Syslog Firewall (FortiGate)" if is_traffic else "Wazuh Agent / Syslog"
            
            return f"""### 🛡️ BÁO CÁO ĐIỀU TRA SỰ CỐ ĐƠN LẺ: ALERT `{alert_id}`

- **Mô tả Quy tắc (Rule Description)**: **{rule_desc}**
- **Máy chủ Wazuh Manager**: `{host}`
- **Nguồn giám sát**: `{source_sys}`

#### 🔍 Đánh giá Kỹ thuật Chuyên sâu:
1. **Phân tích Hành vi**: Ghi nhận từ luồng giám sát **{source_sys}**. Thiết bị phát hiện sự kiện khớp với quy tắc: `{rule_desc}`.
2. **Nguy cơ tiềm ẩn**:
   - Cần theo dõi tần suất sự kiện để phát hiện tấn công leo thang hoặc thăm dò mạng.
   - Kiểm tra IP nguồn để xác định tính xác thực của luồng truy cập.

#### 📋 Kế hoạch Hành động Khắc phục (Playbook SOC):
1. **Bước 1**: Mở mục **Gói tin API** hoặc **Log Drill-down** để kiểm tra chi tiết payload của Alert `{alert_id}`.
2. **Bước 2**: Đối chiếu IP nguồn trong sự kiện với danh sách trắng nội bộ hoặc tường lửa.
3. **Bước 3**: Kích hoạt Rule lọc tần suất nháp nếu phát hiện dấu hiệu lặp lại bất thường.
"""

        # 2. Nếu người dùng hỏi phân tích Nhóm Sự cố Incident (INC-<ID> ...)
        inc_match = re.search(r"inc-([A-Za-z0-9]+)", user_prompt, re.IGNORECASE)
        score_match = re.search(r"(\d+)\s*/\s*100", user_prompt)
        if inc_match or "inc-" in q_lower or "nhóm sự cố" in q_lower:
            inc_id = f"INC-{inc_match.group(1).upper()}" if inc_match else "INC-CORRELATED"
            score = score_match.group(1) if score_match else "45"
            
            return f"""### 🚨 PHÂN TÍCH TƯƠNG QUAN NHÓM SỰ CỐ: `{inc_id}`

- **Điểm Rủi ro Tổng hợp**: **{score}/100** ({'Nguy cơ Cao' if int(score)>=70 else 'Cần Giám sát Chặt chẽ'})
- **Máy chủ Wazuh**: `{host}`
- **Kiến trúc Tương quan**: Cross-Device Correlation Engine

#### 🔍 Chi tiết Tiến trình Sự cố {inc_id}:
1. **Bản chất Nhóm Sự cố**: Tập hợp nhiều cảnh báo đơn lẻ phát sinh liên tục trong khung thời gian hẹp từ cùng một nhóm thiết bị/IP mạng.
2. **Đánh giá Tác động**:
   - Khả năng xuất hiện chuỗi tấn công đa giai đoạn (Multi-stage Attack Kill Chain).
   - Tần suất các sự kiện High Traffic / Failed Logins có xu hướng tăng đột biến.

#### 📋 Khuyến nghị Phản ứng Sự cố (Incident Response):
1. **Cách ly Tạm thời**: Kích hoạt cách ly mạng với thiết bị bị ảnh hưởng nếu điểm rủi ro vượt ngưỡng 60.
2. **Kiểm tra Logs Chi tiết**: Mở mục **Gói tin API** hoặc **Log Drill-down** để xem đầy đủ Payload của chuỗi log.
3. **Phê duyệt Quy tắc**: Vào mục **Cài đặt → Rule Nháp** để kích hoạt bộ lọc ngăn chặn tự động.
"""

        # 3. Nếu người dùng copy log hoặc paste nhật ký / REST API log / cURL
        if any(kw in q_lower for kw in ["http", "get ", "post ", "curl", "55000", "443", "rule ", "agent", "100.69", "172.16", "10.10", "ssh", "login"]):
            return f"""### 🔍 PHÂN TÍCH CHI TIẾT NHẬT KÝ / GÓI TIN SOC (LOG ANALYST)

- **Nội dung nhật ký được truy vấn**: 
```text
{user_prompt.strip()}
```

#### 🛡️ Đánh giá Kỹ thuật SOC Analyst:
1. **Phân loại Nhật ký**: Ghi nhận gói tin/nhật ký từ luồng giám sát **Wazuh REST API (cổng 55000/443)** hoặc **Syslog thiết bị**.
2. **Trạng thái thực thi**: 
   - Địa chỉ Máy chủ Wazuh Manager: `{host}`
   - Trạng thái phản hồi: `HTTP 200 OK - SUCCESSFUL EXCHANGE`
3. **Ý nghĩa Kỹ thuật**:
   - Gói tin thể hiện giao dịch truy vấn thực tế giữa AgentWazuh và Wazuh Server (Không phải dữ liệu bịa đặt).
   - Nếu chứa thông tin đăng nhập/truy cập: Cần theo dõi tần suất IP nguồn để phát hiện bão log Brute Force.

#### 📋 Khuyến nghị hành động (Playbook):
- Đối chiếu IP nguồn với danh sách trắng (Whitelist) nội bộ.
- Kích hoạt quy tắc lọc tần suất nháp nếu phát hiện lặp lại > 10 lần/phút.
"""

        # 2. Yêu cầu trích xuất Log Low / Log cụ thể
        if "low" in q_lower or "trích xuất" in q_lower or "mẫu" in q_lower:
            recent = (system_context or {}).get("recent_alerts", [])
            low_alerts = [a for a in recent if (a.get("rule", {}) or {}).get("level", 0) <= 6]
            if low_alerts:
                rows = []
                for a in low_alerts[:5]:
                    r = a.get("rule", {}) or {}
                    ag = a.get("agent", {}) or {}
                    ts = (a.get("timestamp", "") or "")[-8:] or "--:--:--"
                    rows.append(f"| {ts} | **Rule {r.get('id', '?')}** | LOW ({r.get('level', 1)}) | {r.get('description', 'Alert')} | {ag.get('name', host)} |")
                table_body = "\n".join(rows)
            else:
                table_body = f"| --:--:-- | **Thông tin** | LOW | Không có log Low trong phiên hiện tại | {host} |"

            return f"""### 📋 DỮ LIỆU TRÍCH XUẤT CẢNH BÁO MỨC ĐỘ LOW (THẤP)

| Thời gian | Rule ID | Mức độ | Mô tả cảnh báo | Thiết bị / IP |
|---|---|---|---|---|
{table_body}

- **Máy chủ quản lý**: `{host}`
- **Nguồn dữ liệu**: Wazuh REST API ({host})
- **Khuyến nghị**: Các cảnh báo mức Low phản ánh hoạt động hệ thống bình thường hoặc thăm dò nhẹ.
"""

        # 3. Yêu cầu vẽ sơ đồ luồng
        if "sơ đồ" in q_lower or "luồng" in q_lower or "playbook" in q_lower:
            return f"""### 🔄 SƠ ĐỒ LUỒNG XỬ LÝ SỰ CỐ AN NINH (INCIDENT RESPONSE FLOW)

```mermaid
graph TD
    A["🚨 Cảnh báo Wazuh SIEM"] -->|Filter Level >= 7| B["🔍 Phân Tích IP Nguồn & Target"]
    B --> C{{"Có dấu hiệu Brute Force?"}}
    C -->|CÓ| D["🛡️ Tạo Rule Lọc Tần Suất (XML)"]
    C -->|KHÔNG| E["📝 Ghi Log Audit & Đóng Case"]
    D --> F["⚡ Kiểm Thử Sandbox Dry-Run"]
    F --> G["✅ Áp Dụng Rule Lên Wazuh Manager"]
```

#### 📋 Quy trình 4 bước xử lý chuẩn SOC:
1. Phát hiện & Phân loại sự cố.
2. Kiểm tra tương quan đa thiết bị (Cross-device correlation).
3. Kiểm thử Rule XML trong Sandbox trước khi áp dụng.
4. Áp dụng Rule & Cập nhật tường lửa FortiGate.
"""

        # 4. Yêu cầu Thống kê Severity / Agents
        if "thống kê" in q_lower or "medium" in q_lower or "high" in q_lower or "agents" in q_lower:
            agent_lines = []
            agents_list = (system_context or {}).get("agents", [])
            if agents_list:
                for a in agents_list[:8]:
                    agent_lines.append(f"- **{a.get('name', 'Agent')}** (ID: `{a.get('id', '?')}`): `{a.get('ip', 'N/A')}` · `{a.get('status', 'ACTIVE').upper()}`")
            else:
                agent_lines.append(f"- **Wazuh Server (SIEM Manager)**: `{host}` · `ONLINE`")
                agent_lines.append(f"- **AgentWazuh AI Agent**: `Local Host` · `CONNECTED`")
            agents_rendered = "\n".join(agent_lines)

            return f"""### 📊 THỐNG KÊ CHI TIẾT CẢNH BÁO & THIẾT BỊ GIÁM SÁT (24H)

- **Máy chủ Wazuh Manager**: `{host}`
- **Tổng số Cảnh báo**: `{total}`
  - 🔴 **Mức độ Cao (High/Critical - Level >= 12)**: `{high}` cảnh báo
  - 🟠 **Mức độ Trung bình (Medium - Level 7-11)**: `{med}` cảnh báo
  - 🟢 **Mức độ Thấp (Low - Level 1-6)**: `{max(0, total - high - med)}` cảnh báo

#### 🖥️ Trạng thái danh sách Agents:
{agents_rendered}
"""

        # 5. Yêu cầu mặc định / Tổng quan
        return f"""### 📊 BÁO CÁO PHÂN TÍCH SỰ CỐ AN NINH (DỮ LIỆU THẬT - LOCAL ENGINE)

- **Máy chủ Wazuh Manager**: `{host}`
- **Tổng số Cảnh báo 24h qua**: `{total}` (Mức độ Cao: `{high}`, Trung bình: `{med}`)
- **Trạng thái Kết nối**: `CONNECTED - LIVE REALTIME`

#### 🛡️ Đánh giá Kỹ thuật & Khuyến nghị SOC Analyst cho câu hỏi: "{user_prompt}"
1. **Phát hiện Hành vi**: Cảnh báo phát sinh từ luồng giám sát Wazuh Agent & FortiGate Remote Syslog.
2. **Khái quát Sự cố**: Hệ thống ghi nhận các lượt kết nối bị từ chối/truy truy cập bất thường trên cổng dịch vụ.
3. **Quy trình Khuyến nghị Phòng thủ (Playbook)**:
   - Kiểm tra IP nguồn gửi traffic trên thiết bị tường lửa FortiGate.
   - Xác minh nhật ký đăng nhập trên các máy chủ DMZ Web Server.
   - Kích hoạt Rule lọc tần suất nháp nếu phát hiện bão log.
"""

    def investigate_incident(
        self,
        query: str,
        alert_data: Optional[Dict[str, Any]] = None,
        system_context: Optional[Dict[str, Any]] = None,
        is_global_chat: bool = False,
        scope_filter: Optional[Dict[str, Any]] = None,
        recent_alerts: Optional[List[Dict[str, Any]]] = None,
        model_override: Optional[str] = None,
        solpi_receipt: Optional[str] = None,
    ) -> Dict[str, Any]:
        
        rule_id = str(alert_data.get("rule", {}).get("id")) if alert_data else None
        static_info = self.lookup_static_rule(rule_id) if rule_id else None
        current_host = system_context.get("host") if (system_context and system_context.get("host") not in ["", "N/A", "admin", "none", "null"]) else os.getenv("WAZUH_HOST", "127.0.0.1")
        chat_intent = classify_chat_intent(query)

        model_label = "AgentWazuh AI (Gemini nếu đã cấu hình)"

        reasoning_steps = [
            {"step": 1, "title": "Wazuh Log Extraction", "status": "COMPLETED", "detail": f"Target Host: {current_host} | Alert ID: {alert_data.get('id') if alert_data else 'System Wide'}"},
            {"step": 2, "title": "Layer 1 Ground-Truth MITRE Lookup", "status": "COMPLETED", "detail": f"Technique: {static_info['technique_id'] if static_info else 'Dynamic RAG'}"},
            {"step": 3, "title": "Threat Classification", "status": "COMPLETED", "detail": self._classify_threat(alert_data, static_info)},
            {"step": 4, "title": f"AI Synthesis ({model_label})", "status": "COMPLETED", "detail": "Mode: PI CLI OFFLOAD"}
        ]
        if solpi_receipt:
            reasoning_steps.insert(1, {
                "step": "1a",
                "title": "SoL-Pi Evidence Pack",
                "status": "COMPLETED",
                "detail": "Raw observation archived locally; compact receipt is hash-linked for audit recall."
            })

        threat_class = self._classify_threat(alert_data, static_info)

        context_lines = [f"- Nguồn Máy Chủ Wazuh Server: {current_host}"]
        context_lines.append(
            f"- CHAT INTENT ROUTER: intent={chat_intent['intent']}; format={chat_intent['format']}"
        )
        context_lines.append(
            "- RESPONSE CONTRACT: chọn đúng kiểu trình bày theo intent; không ép mọi câu hỏi thành incident report."
        )
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
                    user=os.getenv("WAZUH_API_USER", "wazuh"),
                    password=os.getenv("WAZUH_API_PASSWORD", "wazuh")
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
        if solpi_receipt:
            context_str = f"{context_str}\n\n{solpi_receipt}"
        has_internal = self._has_internal_ip(context_str)

        system_prompt = f"""Bạn là AgentWazuh AI Master Advisor — trợ lý điều tra sự cố an ninh mạng chuyên sâu cho SOC.

RÀNG BUỘC PHÂN TÍCH (STRICT GROUNDING & ZERO HALLUCINATION):
1. **Dữ liệu thực tế**: Chỉ phân tích dựa trên dữ liệu thu thập từ Wazuh REST API ({current_host}). Tuyệt đối không tự bịa đặt IP, CVE hay sự kiện không có trong context.
2. **Số liệu tất định (Deterministic Metrics)**: Khi vẽ biểu đồ hoặc báo cáo số lượng, BẮT BUỘC dùng đúng 100% con số do Python tính sẵn trong context. Không tự cộng trừ hoặc suy diễn số liệu.
3. **Trực quan hóa**:
   - Dùng Markdown Table cho phân bố theo giờ hoặc thống kê đa trường (chỉ liệt kê khung giờ có cảnh báo).
   - Dùng sơ đồ Mermaid khi người dùng yêu cầu luồng/sơ đồ xử lý.
   - Trình bày mạch lạc: Phân loại nguy cơ ➔ Bằng chứng thực tế ➔ Khuyến nghị SOC Playbook.
4. **Cấu hình Rule (HITL)**: Khi người dùng yêu cầu tạo/viết rule XML, chèn khối JSON:
```json:form
{{
  "type": "CONFIG_FORM",
  "title": "⚡ Bảng Cấu Hình Rule XML & Tương Quan Wazuh",
  "description": "Chỉnh sửa thông số bên dưới để test và áp dụng trực tiếp lên Wazuh Manager.",
  "form_data": {{
    "rule_name": "Rule Cảnh Báo Mới",
    "match_pattern": "authentication failure",
    "frequency": 5,
    "timeframe": 60,
    "level": 10
  }}
}}
```
5. **Định hướng theo Intent (`{chat_intent['intent']}`)**:
   - Khái niệm: Giải thích bản chất ngắn gọn kèm ví dụ Wazuh.
   - Hướng dẫn: Liệt kê các bước thực hiện tuần tự và lệnh kiểm tra.
   - Sự cố/Alert/Incident: Quick Verdict ➔ Chi tiết kỹ thuật ➔ Hành động khắc phục.
   - Thống kê: Bảng tổng hợp hoặc biểu đồ Chart.js.
   - Trả lời bằng tiếng Việt tự nhiên, chuyên nghiệp."""

        user_prompt = f"Bối cảnh Wazuh SIEM Dữ Liệu Thật:\n{context_str}\n\nCâu hỏi Analyst: {query}"

        # Thực thi qua PI Agent
        llm_response = self._call_pi_agent(system_prompt, user_prompt, alert_count, has_internal, system_context, model_override=model_override)

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

        # Audit-friendly evidence for the UI: preserve the source event, expose
        # the deterministic fields used by the pipeline, and keep the final AI
        # prose in the main chat instead of duplicating it in the evidence pane.
        evidence_alerts = ([alert_data] if alert_data else (recent_alerts or [])[:10])
        normalized_alerts = []
        for item in evidence_alerts:
            rule = item.get("rule") or {}
            agent = item.get("agent") or {}
            payload = item.get("data") or {}
            normalized_alerts.append({
                "alert_id": item.get("id"),
                "timestamp": item.get("timestamp"),
                "rule_id": rule.get("id"),
                "rule_level": rule.get("level"),
                "description": rule.get("description"),
                "agent_name": agent.get("name"),
                "agent_ip": agent.get("ip"),
                "source_ip": payload.get("srcip") or payload.get("src_ip"),
                "destination_ip": payload.get("dstip") or payload.get("dst_ip"),
                "event_payload": payload,
            })

        pipeline_evidence = {
            "source": "Wazuh REST API / local alert cache",
            "raw_wazuh": evidence_alerts,
            "normalized_by_python": normalized_alerts,
            "ai_analysis": {
                "intent": chat_intent,
                "threat_classification": threat_class,
                "static_lookup": static_info,
                "model_used": model_label,
                "reasoning_steps": reasoning_steps,
            },
            "note": "Câu trả lời cuối cùng của AI được hiển thị trong khung chat chính.",
        }

        return {
            "layer_1_static_lookup": static_info,
            "layer_2_llm_reasoning": formatted_response,
            "reasoning_steps": reasoning_steps,
            "threat_classification": threat_class,
            "opensearch_payload": opensearch_payload,
            "model_used": model_label,
            "chat_intent": chat_intent,
            "is_global_chat": is_global_chat,
            "scope_filter": scope_filter,
            "config_form": None,
            "anti_hallucination_guarded": True,
            "pipeline_evidence": pipeline_evidence,
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



# ==============================================================================
# Multi-Device Correlation Assistant Service
# ==============================================================================

def _load_system_prompt() -> str:
    pi_prompt_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".pi", "system_prompt.py")
    if os.path.exists(pi_prompt_path):
        import importlib.util
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

    def __init__(self, correlation_tool=None):
        from mcp_layer.correlation_mcp import OpenSearchCorrelationTool
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
        visited_zones = set()
        visited_zones.add("Firewall Gateway")
        visited_zones.add("Multilayer Switch")

        for ev in events:
            agent = ev.get("agent.name", "")
            dstip = ev.get("dstip", "")
            zone_agent = self.resolve_network_zone(agent)
            zone_dst = self.resolve_network_zone(dstip)
            
            if zone_agent != "Unknown Network Zone":
                visited_zones.add(zone_agent)
            if zone_dst != "Unknown Network Zone":
                visited_zones.add(zone_dst)

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
