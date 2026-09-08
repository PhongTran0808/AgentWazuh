import os
import json
import ssl
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, Any, List, Union, Optional

class OpenSearchCorrelationTool:
    """
    OpenSearch Correlation MCP Tool:
    Queries OpenSearch (Port 443 / SSL) for retro-hunting multi-device attack indicators.
    Filters wazuh-alerts-4.x-* within [base_timestamp - window, base_timestamp + window].
    Returns token-optimized concise JSON array or a graceful degradation message.
    """

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None,
                 username: Optional[str] = None, password: Optional[str] = None):
        # Auto-detect host: if /var/ossec exists or no OPENSEARCH_HOST set, default to 127.0.0.1
        default_host = "127.0.0.1" if os.path.exists("/var/ossec") else "127.0.0.1"
        self.host = host or os.getenv("OPENSEARCH_HOST") or os.getenv("WAZUH_API_HOST") or default_host
        self.port = port or int(os.getenv("OPENSEARCH_PORT", "443"))
        self.username = username or os.getenv("OPENSEARCH_USER", "admin")
        self.password = password or os.getenv("OPENSEARCH_PASS", "admin")
        self.verify_certs = os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"


    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parses various ISO 8601 timestamp formats into datetime object."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ]
        
        # Clean trailing Z if needed
        clean_ts = ts_str.strip()
        
        for fmt in formats:
            try:
                return datetime.strptime(clean_ts, fmt)
            except ValueError:
                continue
                
        # Try handling ISO format via datetime.fromisoformat for python 3.7+
        try:
            return datetime.fromisoformat(clean_ts.replace("Z", "+00:00"))
        except Exception:
            # Fallback to current UTC time if unparseable
            return datetime.utcnow()

    def _format_iso(self, dt: datetime) -> str:
        """Formats datetime to ISO 8601 string for OpenSearch range query."""
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def build_dsl_query(self, target_ip: str, start_iso: str, end_iso: str) -> Dict[str, Any]:
        """Builds OpenSearch DSL query searching target_ip in wazuh-alerts-4.x-*."""
        return {
            "size": 100,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_iso,
                                    "lte": end_iso,
                                    "format": "strict_date_optional_time||epoch_millis"
                                }
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {"term": {"data.srcip": target_ip}},
                                    {"term": {"data.dstip": target_ip}},
                                    {"term": {"agent.ip": target_ip}},
                                    {"match": {"data.srcip": target_ip}},
                                    {"match": {"data.dstip": target_ip}},
                                    {"query_string": {"query": f'"{target_ip}"'}}
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ]
                }
            },
            "_source": [
                "@timestamp", "timestamp", "agent.id", "agent.name", "agent.ip",
                "rule.id", "rule.description", "rule.level", "data.srcip", "data.dstip",
                "data.srcport", "data.dstport", "decoder.name"
            ],
            "sort": [{"@timestamp": {"order": "asc"}}]
        }

    def query_opensearch(self, dsl_query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Sends HTTPS query to OpenSearch cluster."""
        protocol = "https" if self.port in [443, 9200] else "http"
        url = f"{protocol}://{self.host}:{self.port}/wazuh-alerts-4.x-*/_search"

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        # Handle Basic Auth
        import base64
        auth_str = f"{self.username}:{self.password}"
        b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
        headers["Authorization"] = f"Basic {b64_auth}"

        data_bytes = json.dumps(dsl_query).encode("utf-8")

        # SSL context configuration
        ssl_ctx = ssl.create_default_context()
        if not self.verify_certs:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as response:
                res_body = json.loads(response.read().decode("utf-8"))
                hits = res_body.get("hits", {}).get("hits", [])
                return hits
        except Exception as e:
            print(f"⚠️ [Correlation MCP Tool] OpenSearch Query Exception: {e}")
            return []

    def search_correlated_events(
        self,
        target_ip: str,
        base_timestamp: str,
        time_window_minutes: int = 15
    ) -> Union[List[Dict[str, Any]], str]:
        """
        Main tool function:
        Retrieves correlated alerts within [base_timestamp - window, base_timestamp + window].
        Returns token-optimized concise JSON array or fallback message.
        """
        graceful_fallback = "Không ghi nhận hoạt động tương quan nào từ IP này trên các thiết bị khác trong khoảng thời gian +/- 15 phút."

        if not target_ip or not target_ip.strip():
            return graceful_fallback

        base_dt = self._parse_timestamp(base_timestamp)
        start_dt = base_dt - timedelta(minutes=time_window_minutes)
        end_dt = base_dt + timedelta(minutes=time_window_minutes)

        start_iso = self._format_iso(start_dt)
        end_iso = self._format_iso(end_dt)

        dsl_query = self.build_dsl_query(target_ip.strip(), start_iso, end_iso)
        raw_hits = self.query_opensearch(dsl_query)

        if not raw_hits:
            return graceful_fallback

        concise_events = []
        for hit in raw_hits:
            src = hit.get("_source", {})
            event_ts = src.get("@timestamp") or src.get("timestamp") or "N/A"
            agent_info = src.get("agent", {})
            agent_name = agent_info.get("name") or agent_info.get("id") or "unknown-agent"
            agent_ip = agent_info.get("ip", "")
            rule_info = src.get("rule", {})
            rule_id = rule_info.get("id", "0000")
            rule_desc = rule_info.get("description", "No description")
            rule_level = rule_info.get("level", 0)
            
            data_info = src.get("data", {})
            src_ip = data_info.get("srcip") or agent_ip or target_ip
            dst_ip = data_info.get("dstip") or "N/A"

            concise_events.append({
                "timestamp": event_ts,
                "agent.name": agent_name,
                "rule.id": rule_id,
                "rule.level": rule_level,
                "rule.description": rule_desc,
                "srcip": src_ip,
                "dstip": dst_ip
            })

        if not concise_events:
            return graceful_fallback

        return concise_events


def search_correlated_events(
    target_ip: str,
    base_timestamp: str,
    time_window_minutes: int = 15
) -> Union[List[Dict[str, Any]], str]:
    """Helper standalone function wrapping OpenSearchCorrelationTool."""
    tool = OpenSearchCorrelationTool()
    return tool.search_correlated_events(target_ip, base_timestamp, time_window_minutes)
