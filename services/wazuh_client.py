import hashlib
import json
import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Dict, Any, List, Optional
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from datetime import datetime
from services.audit_logger import audit_logger

# --- SSL Configuration ---
_VERIFY_SSL_ENV = os.getenv("WAZUH_VERIFY_SSL", "false").strip().lower()
_SSL_VERIFY: bool = _VERIFY_SSL_ENV not in ("false", "0", "no")

if not _SSL_VERIFY:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("WazuhClient")

if not _SSL_VERIFY:
    logger.warning(
        "⚠️  [SECURITY WARNING] WAZUH_VERIFY_SSL=false — SSL verification DISABLED. "
        "Acceptable for lab/self-signed cert only. Set WAZUH_VERIFY_SSL=true in production."
    )

# JWT Token TTL: Wazuh default JWT validity = 900s.
# Proactively refresh at 840s (14 min) to avoid expiry mid-request.
TOKEN_TTL_SECONDS: int = 840

# Global ring buffer storing real-time API exchange logs with timestamps
LIVE_API_LOGS: deque = deque(maxlen=100)

def record_live_api_log(direction: str, method: str, url: str, status_code: int, detail: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    LIVE_API_LOGS.appendleft({
        "timestamp": timestamp,
        "direction": direction,
        "method": method,
        "url": url,
        "status_code": status_code,
        "detail": detail
    })


class WazuhClient:
    """
    Client kết nối chính thức tới Wazuh Manager (REST API 55000 + Dashboard Proxy 443).

    Port Reference:
      - 55000: Wazuh Manager REST API (JWT Bearer Auth)
      - 443:   OpenSearch/Dashboard Console Proxy (Cookie Session)
      - 1515:  Agent enrollment/authentication (agent-auth binary)
      - 1514:  Agent event transport (wazuh-agent -> manager, TCP/UDP)
      - 514:   Syslog listener for agentless devices (if configured in ossec.conf)

    Token Cache:
      - JWT token cached with TTL of TOKEN_TTL_SECONDS (840s).
      - TOKEN_REUSED: token still valid, no re-auth needed.
      - TOKEN_REFRESHED: token expired or missing, re-authenticated.
      - AUTH_RETRY: received HTTP 401 mid-request, cleared cache, re-authenticated once.
      - AUTH_FAILED: re-authentication after 401 also failed.

    SSL Verification:
      - Controlled by WAZUH_VERIFY_SSL env variable (default: true).
      - Set WAZUH_VERIFY_SSL=false for self-signed cert lab environments.
    """

    def __init__(
        self,
        host: str = "172.16.175.145",
        port: int = 55000,
        user: str = "agentwazuh",
        password: str = "",
        dashboard_user: str = "admin",
        dashboard_pass: str = ""
    ):
        self.host = host if (host and host not in ["127.0.0.1", "localhost", "admin"]) else "172.16.175.145"
        self.port = port
        self.user = user
        # Load from env if not explicitly provided — never log the actual value
        self.password = password or os.getenv("WAZUH_API_PASSWORD", "")
        self.dashboard_user = dashboard_user
        self.dashboard_pass = dashboard_pass or os.getenv("INDEXER_PASSWORD", "admin")
        self.base_url = f"https://{self.host}:{self.port}"
        self._ssl_verify: bool = _SSL_VERIFY

        # --- Token Cache ---
        self._jwt_token: Optional[str] = None
        self._token_acquired_at: float = 0.0
        self._token_expires_at: float = 0.0

        # --- Dashboard Session Cache (Port 443) ---
        # Cookie session reused for SESSION_CACHE_TTL seconds to avoid re-login on every alert fetch.
        self._dashboard_session: Optional[requests.Session] = None
        self._dashboard_session_acquired_at: float = 0.0
        SESSION_CACHE_TTL = 240  # 4 minutes (dashboard session typically valid 15-30min)
        self._session_cache_ttl: int = SESSION_CACHE_TTL

        self.last_auth_error = None
        self._conn_history: deque = deque(maxlen=50)

    # --- Legacy property for backward compatibility ---
    @property
    def jwt_token(self) -> Optional[str]:
        return self._jwt_token

    @jwt_token.setter
    def jwt_token(self, value: Optional[str]):
        self._jwt_token = value

    def _record_conn_attempt(self, success: bool, error_type: str = None) -> None:
        self._conn_history.append({
            "timestamp": time.time(),
            "success": success,
            "error_type": error_type
        })

    def _is_token_valid(self) -> bool:
        """Check whether cached JWT token is still within its valid TTL window."""
        if not self._jwt_token:
            return False
        remaining = self._token_expires_at - time.time()
        return remaining > 30  # 30s safety margin

    def _get_valid_token(self) -> Optional[str]:
        """
        Return a valid JWT token, reusing from cache or refreshing as needed.
        """
        if self._is_token_valid():
            remaining = int(self._token_expires_at - time.time())
            logger.debug(f"[TOKEN_REUSED] JWT valid ({remaining}s remaining)")
            return self._jwt_token

        logger.info("[TOKEN_REFRESHED] JWT expired or missing — re-authenticating...")
        success = self.authenticate()
        return self._jwt_token if success else None

    def get_agentwazuh_connection_state(self, window_seconds: int = 600) -> dict:
        now = time.time()
        recent = [x for x in self._conn_history if now - x["timestamp"] < window_seconds]
        if not recent:
            state = "chua_ket_noi"
        elif all(x["success"] for x in recent):
            state = "da_ket_noi"
        elif all(not x["success"] for x in recent):
            state = "chua_ket_noi"
        else:
            state = "chap_chon"
        success_count = sum(1 for x in recent if x["success"])
        fail_count = len(recent) - success_count
        return {
            "state": state,
            "window_seconds": window_seconds,
            "total_attempts": len(recent),
            "success_count": success_count,
            "fail_count": fail_count,
            "fail_rate_pct": round(fail_count / len(recent) * 100, 1) if recent else 0
        }

    def authenticate(self) -> bool:
        """Authenticate to Wazuh REST API (Port 55000). Caches JWT with TTL."""
        auth_url = f"https://{self.host}:{self.port}/security/user/authenticate"
        try:
            logger.info(f"[Wazuh API 55000] Authenticating -> {auth_url} (User: {self.user})")
            audit_logger.log_wazuh_api(
                action="REQUEST /security/user/authenticate",
                status="INFO",
                message=f"Gửi xác thực tài khoản {self.user}",
                payload={"host": self.host, "port": self.port, "user": self.user}
            )
            res = requests.post(
                auth_url,
                auth=(self.user, self.password),
                verify=self._ssl_verify,
                timeout=4.0
            )
            if res.status_code == 200:
                token = res.json().get("data", {}).get("token")
                self._jwt_token = token
                self._token_acquired_at = time.time()
                self._token_expires_at = self._token_acquired_at + TOKEN_TTL_SECONDS
                self.base_url = f"https://{self.host}:{self.port}"
                self.last_auth_error = None
                logger.info(f"✅ [TOKEN_REFRESHED] JWT acquired. Valid for {TOKEN_TTL_SECONDS}s.")
                audit_logger.log_wazuh_api(
                    action="RESPONSE 200 OK",
                    status="SUCCESS",
                    message=f"Nhận JWT Token (hết hạn sau {TOKEN_TTL_SECONDS}s)",
                    payload={"user": self.user, "ttl_seconds": TOKEN_TTL_SECONDS}
                )
                self._record_conn_attempt(True)
                return True
            elif res.status_code == 401:
                self._jwt_token = None
                self._token_expires_at = 0.0
                self.last_auth_error = f"Sai thông tin đăng nhập (User: {self.user})"
                logger.warning(f"❌ [AUTH_FAILED] 401 Unauthorized")
                audit_logger.log_wazuh_api(
                    action="AUTH_FAILED",
                    status="ERROR",
                    message=f"Xác thực thất bại HTTP 401: {self.last_auth_error}",
                    payload={"user": self.user, "status_code": 401}
                )
                self._record_conn_attempt(False, "auth_401")
                return False
            else:
                self._jwt_token = None
                self._token_expires_at = 0.0
                self.last_auth_error = f"Xác thực thất bại (HTTP {res.status_code} từ {self.host})"
                logger.warning(f"❌ [AUTH_FAILED] HTTP {res.status_code}")
                audit_logger.log_wazuh_api(
                    action="AUTH_FAILED",
                    status="ERROR",
                    message=f"Xác thực thất bại: {self.last_auth_error}",
                    payload={"status_code": res.status_code}
                )
                self._record_conn_attempt(False, f"http_{res.status_code}")
                return False
        except Exception as e:
            self._jwt_token = None
            self._token_expires_at = 0.0
            self.last_auth_error = f"Không thể kết nối tới {self.host}:{self.port} ({e})"
            logger.error(f"❌ [AUTH_FAILED] Connection Error: {e}")
            audit_logger.log_wazuh_api(
                action="CONNECTION_ERROR",
                status="ERROR",
                message=f"Lỗi kết nối API: {e}",
                payload={"error": str(e)}
            )
            self._record_conn_attempt(False, "connection_error")
            return False

    def _request_with_auth_retry(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Execute authenticated request. Handles HTTP 401 by clearing token cache
        and retrying ONCE. No infinite retry loops.
        """
        token = self._get_valid_token()
        if not token:
            return None

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"

        try:
            resp = requests.request(method, url, headers=headers, verify=self._ssl_verify, **kwargs)

            if resp.status_code == 401:
                logger.warning(f"⚠️  [AUTH_RETRY] 401 on {url} — clearing cache, retrying once...")
                self._jwt_token = None
                self._token_expires_at = 0.0
                new_token = self._get_valid_token()
                if not new_token:
                    logger.error("[AUTH_FAILED] Re-auth after 401 failed.")
                    return resp
                headers["Authorization"] = f"Bearer {new_token}"
                resp = requests.request(method, url, headers=headers, verify=self._ssl_verify, **kwargs)
                if resp.status_code == 401:
                    logger.error("[AUTH_FAILED] Retry also 401. Aborting.")
            return resp
        except Exception as e:
            logger.error(f"❌ [REQUEST_ERROR] {method} {url}: {e}")
            return None

    def _get_dashboard_session(self) -> Optional[requests.Session]:
        """
        Authenticate to Wazuh Dashboard (Port 443) using dashboard credentials.
        Session is CACHED for up to SESSION_CACHE_TTL seconds to avoid re-login overhead
        on every alert fetch (previously added 1-2s per call).
        """
        # Reuse cached session if still fresh
        if self._dashboard_session is not None:
            age = time.time() - self._dashboard_session_acquired_at
            if age < self._session_cache_ttl:
                logger.debug(f"[SESSION_REUSED] Dashboard session reused ({age:.0f}s old)")
                return self._dashboard_session

        # Session expired or missing — re-login
        logger.info(f"[SESSION_REFRESH] Dashboard session expired or missing — logging in to https://{self.host}/auth/login")
        try:
            s = requests.Session()
            s.verify = self._ssl_verify
            r = s.post(
                f"https://{self.host}/auth/login",
                json={"username": self.dashboard_user, "password": self.dashboard_pass},
                headers={"osd-xsrf": "true", "Content-Type": "application/json"},
                timeout=4
            )
            if r.status_code == 200:
                self._dashboard_session = s
                self._dashboard_session_acquired_at = time.time()
                logger.info("✅ [SESSION_REFRESHED] Dashboard session authenticated and cached.")
                return s
            else:
                logger.warning(f"❌ [Dashboard 443] Login failed HTTP {r.status_code}")
                self._dashboard_session = None
        except Exception as e:
            logger.error(f"❌ [Dashboard 443] Exception: {e}")
            self._dashboard_session = None
        return None

    def get_system_status(self) -> Dict[str, Any]:
        """Fetch system status & active agents list from Wazuh Manager API (Port 55000)."""
        token = self._get_valid_token()
        if not token:
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

        try:
            res = self._request_with_auth_retry("GET", f"{self.base_url}/manager/status", timeout=4.0)
            if res is None or res.status_code != 200:
                return {"status": "offline", "wazuh_host": self.host, "agents": [],
                        "total_agents": 0, "active_agents": 0, "disconnected_agents": 0,
                        "error": f"Manager status check failed"}

            agents_url = f"{self.base_url}/agents?limit=500"
            agents_res = self._request_with_auth_retry("GET", agents_url, timeout=4.0)
            agents = []
            if agents_res and agents_res.status_code == 200:
                agents = agents_res.json().get("data", {}).get("affected_items", [])
                record_live_api_log(
                    "INCOMING_RESPONSE", "GET", agents_url, 200,
                    f"FETCHED AGENTS: {len(agents)} registered agents from {self.host}:55000"
                )

            active_cnt = sum(1 for a in agents if str(a.get("status", "")).lower() == "active")
            disconn_cnt = sum(1 for a in agents if str(a.get("status", "")).lower() == "disconnected")

            ver_res = self._request_with_auth_retry("GET", f"{self.base_url}/manager/info", timeout=4.0)
            version = "Wazuh v4.14.7"
            if ver_res and ver_res.status_code == 200:
                version = ver_res.json().get("data", {}).get("affected_items", [{}])[0].get("version", version)

            self._record_conn_attempt(True)
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
            self._record_conn_attempt(False, "get_system_status_exception")
            return {
                "status": "offline",
                "version": "Unknown",
                "wazuh_host": self.host,
                "agents": [],
                "total_agents": 0,
                "active_agents": 0,
                "disconnected_agents": 0,
                "error": f"Không thể kết nối tới {self.host} ({e})"
            }

    def get_alert_stats_aggregated(self, hours_back: int = 720, tz_offset_hours: int = 7) -> dict:
        """Lấy thống kê alert qua OpenSearch Aggregation (port 443)."""
        if not self.host:
            return {"total_24h": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "error": "Chưa cấu hình Host"}

        try:
            session = self._get_dashboard_session()
            if not session:
                return {"total_24h": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                        "error": "Không thể đăng nhập Dashboard 443"}

            aggs_dsl = {
                "size": 0,
                "query": {"range": {"timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}},
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
                return {"total_24h": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                        "error": f"HTTP {r.status_code}"}

            res_json = r.json()
            total = res_json.get("hits", {}).get("total", {}).get("value", 0)
            buckets = res_json.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
            sev_map = {b.get("key"): b.get("doc_count", 0) for b in buckets}

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
                "critical": sev_map.get("critical", 0),
                "high": sev_map.get("high", 0),
                "medium": sev_map.get("medium", 0),
                "low": sev_map.get("low", 0),
                "hourly_local": hourly_local,
                "non_zero_hours": non_zero_hours,
                "timezone": f"UTC+{tz_offset_hours} (Giờ Việt Nam)",
                "error": None
            }
        except Exception as e:
            return {"total_24h": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "error": str(e)}

    def _fetch_alerts_opensearch(self, search_dsl: dict, timeout: int = 6) -> list:
        """Internal helper: run a DSL search on OpenSearch via Dashboard Proxy."""
        session = self._get_dashboard_session()
        if not session:
            return []
        try:
            audit_logger.log_indexer(
                action="SEARCH wazuh-alerts-4.x-*",
                status="INFO",
                message="Truy vấn DSL: Lọc cảnh báo gần nhất",
                payload=search_dsl
            )
            r = session.post(
                f"https://{self.host}/api/console/proxy?path=wazuh-alerts-4.x-*%2F_search&method=GET",
                json=search_dsl,
                headers={"osd-xsrf": "true", "Content-Type": "application/json"},
                timeout=timeout
            )
            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                audit_logger.log_indexer(
                    action="RECEIVE_PAYLOAD",
                    status="SUCCESS",
                    message=f"Nhận về {len(hits)} alerts gần nhất từ OpenSearch",
                    payload={"total_hits": len(hits)}
                )
                return [
                    {
                        "id": h.get("_id", h.get("_source", {}).get("id", "")),
                        "timestamp": h.get("_source", {}).get("timestamp", ""),
                        "rule": h.get("_source", {}).get("rule", {}),
                        "agent": h.get("_source", {}).get("agent", {}),
                        "data": h.get("_source", {}).get("data", {}),
                        "location": h.get("_source", {}).get("location", ""),
                        "full_log": h.get("_source", {}).get("full_log", "")
                    }
                    for h in hits
                ]
        except Exception as e:
            logger.error(f"[OpenSearch Query] Error: {e}")
        return []

    def get_latest_alerts(self, limit: int = 200, hours_back: int = 720) -> list:
        """
        Fetch live alerts for UI Preview (fast path, capped at `limit`).
        For correlation, use get_alerts_for_correlation() instead.
        """
        if not self.host:
            return []
        search_dsl = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"range": {"timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}},
            "_source": [
                "timestamp", "id",
                "rule.id", "rule.level", "rule.description", "rule.groups",
                "agent.id", "agent.name", "agent.ip",
                "data", "location", "full_log"
            ]
        }
        return self._fetch_alerts_opensearch(search_dsl)

    def get_alerts_for_correlation(self, hours_back: int = 24, max_results: int = 1000,
                                   agent_id: Optional[str] = None,
                                   source_ip: Optional[str] = None) -> list:
        """
        Dedicated alert retrieval for the correlation engine.
        Independent from UI preview cache — uses its own time window (default 24h).
        Supports optional agent_id / source_ip filtering for targeted correlation.
        NOT capped at 200 — fetches up to max_results for comprehensive incident coverage.
        """
        if not self.host:
            return []

        must_clauses = [
            {"range": {"timestamp": {"gte": f"now-{hours_back}h", "lte": "now"}}}
        ]
        if agent_id:
            must_clauses.append({"term": {"agent.id": agent_id}})
        if source_ip:
            must_clauses.append({"term": {"data.srcip": source_ip}})

        search_dsl = {
            "size": max_results,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must_clauses}},
            "_source": [
                "timestamp", "id",
                "rule.id", "rule.level", "rule.description", "rule.groups",
                "agent.id", "agent.name", "agent.ip",
                "data.srcip", "data.dstip", "data.devname",
                "location", "full_log"
            ]
        }
        alerts = self._fetch_alerts_opensearch(search_dsl, timeout=10)
        logger.info(f"[CORRELATION_RETRIEVAL] Fetched {len(alerts)} alerts (last {hours_back}h)")
        return alerts
