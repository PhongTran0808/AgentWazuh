import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("WazuhClient")


class WazuhClient:
    """
    Client kết nối chính thức tới Wazuh Manager (REST API 55000 + Dashboard Proxy 443).
    - Cổng 55000 (REST API): Xác thực JWT Token qua (user, password) -> Mặc định wazuh / wazuh.
    - Cổng 443 (Dashboard): Xác thực Session Cookie qua (dashboard_user, dashboard_pass) -> Mặc định admin / admin.
    """

    def __init__(
        self,
        host: str = "192.168.1.248",
        port: int = 55000,
        user: str = "wazuh",
        password: str = "wazuh",
        dashboard_user: str = "admin",
        dashboard_pass: str = "admin"
    ):
        self.host = host if host not in ["127.0.0.1", "localhost", ""] else "192.168.1.248"
        self.port = port
        self.user = user
        self.password = password
        self.dashboard_user = dashboard_user
        self.dashboard_pass = dashboard_pass
        self.base_url = f"https://{self.host}:{self.port}"
        self.jwt_token = None
        self.last_auth_error = None

    def authenticate(self) -> bool:
        """Strict authentication to Wazuh REST API (Port 55000) using (self.user, self.password)."""
        auth_url = f"https://{self.host}:{self.port}/security/user/authenticate"
        try:
            logger.info(f"🔑 [Wazuh API 55000]: Gửi Yêu Cầu Xác Thực tới {auth_url} (User: {self.user})...")
            res = requests.post(auth_url, auth=(self.user, self.password), verify=False, timeout=4.0)
            if res.status_code == 200:
                self.jwt_token = res.json().get("data", {}).get("token")
                self.base_url = f"https://{self.host}:{self.port}"
                self.last_auth_error = None
                logger.info(f"✅ [Wazuh API 55000]: Authenticated Successfully! JWT Token acquired.")
                return True
            elif res.status_code == 401:
                self.last_auth_error = f"Sai thông tin đăng nhập Wazuh Manager API (User: {self.user})"
                logger.warning(f"❌ [Wazuh API 55000]: 401 Unauthorized ({self.last_auth_error})")
                return False
            else:
                self.last_auth_error = f"Xác thực thất bại (Mã HTTP {res.status_code} từ {self.host})"
                logger.warning(f"❌ [Wazuh API 55000]: HTTP {res.status_code}")
                return False
        except Exception as e:
            self.last_auth_error = f"Không thể kết nối tới Wazuh Manager tại https://{self.host}:{self.port} ({e})"
            logger.error(f"❌ [Wazuh API 55000]: Connection Error ({e})")
            return False

    def _get_dashboard_session(self) -> Optional[requests.Session]:
        """Authenticate to Wazuh Dashboard (Port 443) using (self.dashboard_user, self.dashboard_pass)."""
        try:
            logger.info(f"🔑 [Wazuh Dashboard 443]: Đăng nhập Console Proxy https://{self.host}/auth/login (User: {self.dashboard_user})...")
            s = requests.Session()
            s.verify = False
            r = s.post(
                f"https://{self.host}/auth/login",
                json={"username": self.dashboard_user, "password": self.dashboard_pass},
                headers={"osd-xsrf": "true", "Content-Type": "application/json"},
                timeout=4
            )
            if r.status_code == 200:
                logger.info(f"✅ [Wazuh Dashboard 443]: Session Authenticated Successfully!")
                return s
            else:
                logger.warning(f"❌ [Wazuh Dashboard 443]: Login Failed HTTP {r.status_code}")
        except Exception as e:
            logger.error(f"❌ [Wazuh Dashboard 443]: Exception ({e})")
        return None

    def get_system_status(self) -> Dict[str, Any]:
        """Fetch real system status & active agents list from Wazuh Manager API."""
        if not self.jwt_token:
            if not self.authenticate():
                return {
                    "status": "offline",
                    "version": "Unknown",
                    "wazuh_host": self.host,
                    "agents": [],
                    "total_agents": 0,
                    "active_agents": 0,
                    "disconnected_agents": 0,
                    "error": self.last_auth_error or "Không thể xác thực với Wazuh API"
                }

        headers = {"Authorization": f"Bearer {self.jwt_token}"}
        try:
            # 1. Check Manager Summary
            res = requests.get(f"{self.base_url}/manager/status", headers=headers, verify=False, timeout=4.0)
            if res.status_code != 200:
                # Token might be expired, re-authenticate once
                if not self.authenticate():
                    return {"status": "offline", "error": self.last_auth_error}
                headers = {"Authorization": f"Bearer {self.jwt_token}"}
                res = requests.get(f"{self.base_url}/manager/status", headers=headers, verify=False, timeout=4.0)

            # 2. Get Agents List
            agents_res = requests.get(f"{self.base_url}/agents?limit=500", headers=headers, verify=False, timeout=4.0)
            agents = []
            if agents_res.status_code == 200:
                agents = agents_res.json().get("data", {}).get("affected_items", [])

            active_cnt = sum(1 for a in agents if str(a.get("status", "")).lower() == "active")
            disconn_cnt = sum(1 for a in agents if str(a.get("status", "")).lower() == "disconnected")

            # 3. Get Manager Version
            ver_res = requests.get(f"{self.base_url}/manager/info", headers=headers, verify=False, timeout=4.0)
            version = "Wazuh v4.14.7"
            if ver_res.status_code == 200:
                version = ver_res.json().get("data", {}).get("affected_items", [{}])[0].get("version", version)

            return {
                "status": "online",
                "version": version,
                "wazuh_host": self.host,
                "agents": agents,
                "total_agents": len(agents),
                "active_agents": active_cnt,
                "disconnected_agents": disconn_cnt,
                "error": None
            }
        except Exception as e:
            return {
                "status": "offline",
                "version": "Unknown",
                "wazuh_host": self.host,
                "agents": [],
                "total_agents": 0,
                "active_agents": 0,
                "disconnected_agents": 0,
                "error": f"Không thể kết nối tới Wazuh Server tại {self.host} ({e})"
            }

    def get_alert_stats_aggregated(self, hours_back: int = 24, tz_offset_hours: int = 7) -> dict:
        """
        Lấy thống kê alert CHÍNH XÁC qua OpenSearch Aggregation (port 443).
        """
        if not self.host:
            return {"total_24h": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "error": "Chưa cấu hình Host"}

        try:
            session = self._get_dashboard_session()
            if not session:
                return {"total_24h": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "error": "Không thể đăng nhập Dashboard 443"}

            aggs_dsl = {
                "size": 0,
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{hours_back}h",
                            "lte": "now"
                        }
                    }
                },
                "aggs": {
                    "by_severity": {
                        "range": {
                            "field": "rule.level",
                            "ranges": [
                                {"key": "low", "to": 7},
                                {"key": "medium", "from": 7, "to": 12},
                                {"key": "high", "from": 12, "to": 15},
                                {"key": "critical", "from": 15}
                            ]
                        }
                    },
                    "hourly": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "1h",
                            "format": "HH"
                        }
                    }
                }
            }

            r = session.post(
                f"https://{self.host}/api/console/proxy?path=wazuh-alerts-4.x-*%2F_search&method=GET",
                json=aggs_dsl,
                headers={"osd-xsrf": "true", "Content-Type": "application/json"},
                timeout=6
            )

            if r.status_code != 200:
                return {"total_24h": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "error": f"HTTP {r.status_code}"}

            res_json = r.json()
            total = res_json.get("hits", {}).get("total", {}).get("value", 0)
            buckets = res_json.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
            
            sev_map = {b.get("key"): b.get("doc_count", 0) for b in buckets}
            critical = sev_map.get("critical", 0)
            high = sev_map.get("high", 0)
            medium = sev_map.get("medium", 0)
            low = sev_map.get("low", 0)

            hourly_buckets = res_json.get("aggregations", {}).get("hourly", {}).get("buckets", [])
            hourly_local = {f"{h:02d}:00": 0 for h in range(24)}
            for hb in hourly_buckets:
                utc_hour = int(hb.get("key_as_string", "00"))
                local_hour = (utc_hour + tz_offset_hours) % 24
                hour_key = f"{local_hour:02d}:00"
                hourly_local[hour_key] = hourly_local.get(hour_key, 0) + hb.get("doc_count", 0)

            non_zero_hours = {k: v for k, v in hourly_local.items() if v > 0}

            return {
                "total_24h": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "hourly_local": hourly_local,
                "non_zero_hours": non_zero_hours,
                "timezone": f"UTC+{tz_offset_hours} (Giờ Việt Nam)",
                "error": None
            }
        except Exception as e:
            return {"total_24h": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "error": str(e)}

    def get_latest_alerts(self, limit: int = 100, hours_back: int = 24) -> list:
        """
        Fetch live security alerts từ OpenSearch Index wazuh-alerts-4.x-* qua OpenSearch Console Proxy (443).
        """
        if not self.host:
            return []

        try:
            session = self._get_dashboard_session()
            if not session:
                return []

            search_dsl = {
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{hours_back}h",
                            "lte": "now"
                        }
                    }
                },
                "_source": [
                    "timestamp", "id",
                    "rule.id", "rule.level", "rule.description", "rule.groups",
                    "agent.id", "agent.name", "agent.ip",
                    "data", "location", "full_log"
                ]
            }

            r = session.post(
                f"https://{self.host}/api/console/proxy?path=wazuh-alerts-4.x-*%2F_search&method=GET",
                json=search_dsl,
                headers={"osd-xsrf": "true", "Content-Type": "application/json"},
                timeout=6
            )

            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                alerts = []
                for h in hits:
                    src = h.get("_source", {})
                    alerts.append({
                        "id": h.get("_id", src.get("id", "")),
                        "timestamp": src.get("timestamp", ""),
                        "rule": src.get("rule", {}),
                        "agent": src.get("agent", {}),
                        "data": src.get("data", {}),
                        "location": src.get("location", ""),
                        "full_log": src.get("full_log", "")
                    })
                return alerts
            return []
        except Exception:
            return []
