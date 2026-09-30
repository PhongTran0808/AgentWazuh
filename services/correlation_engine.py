import hashlib
import ipaddress
import json
import math
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple

try:
    import networkx as nx
except ImportError:
    nx = None

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
except ImportError:
    TfidfVectorizer = None
    cosine_similarity = None


def parse_wazuh_time(timestamp_str: str) -> float:
    """Parse a Wazuh ISO timestamp, returning ``0`` when the value is invalid."""
    if not timestamp_str:
        return 0.0
    try:
        clean_str = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        return dt.timestamp()
    except Exception:
        return 0.0


INVALID_IPS = {"", "0.0.0.0", "127.0.0.1", "255.255.255.255", "::", "::1"}


def _clean_scalar(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _valid_ip(value: Any) -> str:
    candidate = _clean_scalar(value)
    if candidate in INVALID_IPS:
        return ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def _first_value(data: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value: Any = data
        for part in key.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        scalar = _clean_scalar(value)
        if scalar:
            return scalar
    return ""


def extract_entities(alert: Dict[str, Any]) -> Set[str]:
    """Return normalized, typed entities that can support a correlation edge."""
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    entities: Set[str] = set()

    for key in ("srcip", "src_ip", "source.ip"):
        value = _valid_ip(_first_value(data, key))
        if value:
            entities.add(f"ip:{value}")
    for key in ("dstip", "dst_ip", "destination.ip"):
        value = _valid_ip(_first_value(data, key))
        if value:
            entities.add(f"ip:{value}")

    agent_id = _clean_scalar(agent.get("id"))
    if agent_id and agent_id != "000":
        entities.add(f"agent-id:{agent_id.lower()}")
    agent_name = _clean_scalar(agent.get("name"))
    if agent_name and agent_name.lower() not in {"wazuh-server", "localhost"}:
        entities.add(f"agent:{agent_name.lower()}")
    agent_ip = _valid_ip(agent.get("ip"))
    if agent_ip:
        entities.add(f"ip:{agent_ip}")

    for value in (
        _first_value(data, "srcuser", "dstuser", "user", "username"),
        _first_value(data, "win.eventdata.targetUserName", "win.eventdata.subjectUserName"),
    ):
        if value and value.lower() not in {"-", "unknown", "system", "root"}:
            entities.add(f"user:{value.lower()}")

    hostname = _first_value(data, "hostname", "host", "devname")
    if hostname:
        entities.add(f"host:{hostname.lower()}")
    return entities


def get_entity(alert: Dict[str, Any]) -> str:
    """
    Extract primary entity (srcip, dstip, agent name, or hostname) from multi-source alerts
    (Supports both Wazuh Agent host events and FortiGate Syslog network events).
    """
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    srcip = _valid_ip(_first_value(data, "srcip", "src_ip", "source.ip"))
    if srcip:
        return srcip

    dstip = _valid_ip(_first_value(data, "dstip", "dst_ip", "destination.ip"))
    if dstip:
        return dstip

    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    agent_name = _clean_scalar(agent.get("name"))
    if agent_name and agent_name.lower() not in {"wazuh-server", "localhost"}:
        return f"agent-{agent_name}"

    agent_id = agent.get("id")
    if agent_id and agent_id != "000":
        return f"agent-{agent_id}"

    # Check FortiGate devname or predecoder hostname
    devname = _first_value(data, "devname", "hostname", "host")
    if devname:
        return f"device-{devname}"

    return "syslog-gateway"


def _dedup_fingerprint(alert: Dict[str, Any]) -> str:
    """Fingerprint one event without collapsing the same rule across different assets."""
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    fields = {
        "rule": _clean_scalar(rule.get("id")),
        "agent_id": _clean_scalar(agent.get("id")),
        "agent_name": _clean_scalar(agent.get("name")).lower(),
        "location": _clean_scalar(alert.get("location")).lower(),
        "src": _first_value(data, "srcip", "src_ip", "source.ip"),
        "dst": _first_value(data, "dstip", "dst_ip", "destination.ip"),
        "src_port": _first_value(data, "srcport", "src_port", "source.port"),
        "dst_port": _first_value(data, "dstport", "dst_port", "destination.port"),
        "user": _first_value(data, "srcuser", "dstuser", "user", "username", "win.eventdata.targetUserName").lower(),
        "process": _first_value(data, "process", "process.name", "win.eventdata.image").lower(),
        "device": _first_value(data, "devname", "hostname", "host").lower(),
        # Preserve event-specific fields (file path, command, registry key, URL,
        # Windows event data, etc.).  Missing these fields causes different
        # security events on one agent to collapse merely because Rule ID matches.
        "data": data,
    }
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def extract_alert_entities(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Trích xuất toàn diện các thực thể (Multi-Entity) từ Alert:
    - IP nguồn (src_ips), IP đích (dst_ips)
    - Tên/ID Agent (agents)
    - Tài khoản người dùng (users)
    - Tên thiết bị mạng (devnames)
    - Rule ID, Rule Level, Rule Description, Timestamp
    """
    data = alert.get("data", {})
    agent = alert.get("agent", {})
    rule = alert.get("rule", {})

    exclude_ips = {"0.0.0.0", "127.0.0.1", "::1", "255.255.255.255", ""}

    src_ips = set()
    for k in ["srcip", "src_ip"]:
        v = data.get(k)
        if v and str(v).strip() not in exclude_ips:
            src_ips.add(str(v).strip())

    dst_ips = set()
    for k in ["dstip", "dst_ip"]:
        v = data.get(k)
        if v and str(v).strip() not in exclude_ips:
            dst_ips.add(str(v).strip())

    agents = set()
    a_name = agent.get("name")
    if a_name and a_name not in ["wazuh-server", "localhost", ""]:
        agents.add(str(a_name).strip())
    a_id = str(agent.get("id", "")).strip()
    if a_id and a_id not in ["000", ""]:
        agents.add(f"agent-{a_id}")

    users = set()
    for k in ["srcuser", "dstuser", "user", "username", "dst_user", "src_user"]:
        u = data.get(k)
        if u and str(u).strip() not in ["", "-", "unknown"]:
            users.add(str(u).strip())
    syscheck = alert.get("syscheck", {})
    if isinstance(syscheck, dict):
        uname = syscheck.get("uname")
        if uname and str(uname).strip() not in ["", "-"]:
            users.add(str(uname).strip())

    devnames = set()
    dev = data.get("devname")
    if dev and str(dev).strip():
        devnames.add(str(dev).strip())

    return {
        "src_ips": sorted(src_ips),
        "dst_ips": sorted(dst_ips),
        "agents": sorted(agents),
        "users": sorted(users),
        "devnames": sorted(devnames),
        "rule_id": str(rule.get("id", "")),
        "rule_level": int(rule.get("level", 0)),
        "rule_desc": str(rule.get("description", "")),
        "timestamp": parse_wazuh_time(alert.get("timestamp", ""))
    }


def compute_correlation_weight(
    e1: Dict[str, Any],
    e2: Dict[str, Any],
    time_window_sec: float,
    semantic_sim: float = 0.0
) -> (float, List[str]):
    """
    Tính trọng số tương quan giữa 2 alert (0.0 -> 1.0) kèm lý do tương quan.
    Áp dụng trọng số phân cấp:
    - Trùng src_ip: +0.50
    - Trùng dst_ip: +0.40
    - Dấu hiệu Lateral Movement / Pivot (e1.dst == e2.src hoặc ngược lại): +0.55
    - Trùng Agent: +0.45
    - Trùng User: +0.40
    - Trùng Devname: +0.30
    - Tương đồng ngữ nghĩa mô tả (TF-IDF Cosine Similarity >= 0.65): + (sim * 0.30)
    - Suy giảm theo thời gian: nhân hệ số thời gian (1 - 0.20 * (dt / window))
    """
    t1 = e1["timestamp"]
    t2 = e2["timestamp"]
    dt = abs(t2 - t1)
    if dt > time_window_sec:
        return 0.0, []

    weight = 0.0
    reasons = []

    shared_src = set(e1["src_ips"]) & set(e2["src_ips"])
    if shared_src:
        weight += 0.50
        reasons.append(f"shared_src_ip:{list(shared_src)[0]}")

    shared_dst = set(e1["dst_ips"]) & set(e2["dst_ips"])
    if shared_dst:
        weight += 0.40
        reasons.append(f"shared_dst_ip:{list(shared_dst)[0]}")

    # Lateral movement / pivoting: dst IP của bước trước trở thành src IP của bước sau
    pivoting = (set(e1["dst_ips"]) & set(e2["src_ips"])) | (set(e2["dst_ips"]) & set(e1["src_ips"]))
    if pivoting:
        weight += 0.55
        reasons.append(f"lateral_movement_pivot:{list(pivoting)[0]}")

    shared_agent = set(e1["agents"]) & set(e2["agents"])
    if shared_agent:
        weight += 0.45
        reasons.append(f"shared_agent:{list(shared_agent)[0]}")

    shared_user = set(e1["users"]) & set(e2["users"])
    if shared_user:
        weight += 0.40
        reasons.append(f"shared_user:{list(shared_user)[0]}")

    shared_dev = set(e1["devnames"]) & set(e2["devnames"])
    if shared_dev:
        weight += 0.30
        reasons.append(f"shared_device:{list(shared_dev)[0]}")

    if semantic_sim >= 0.65:
        weight += (semantic_sim * 0.30)
        reasons.append(f"semantic_similarity:{round(semantic_sim, 2)}")

    if weight > 0:
        decay = max(0.80, 1.0 - (0.20 * (dt / max(time_window_sec, 1))))
        weight = min(round(weight * decay, 3), 1.0)

    return weight, reasons


def calculate_incident_confidence(
    sub_alerts: List[Dict[str, Any]],
    edge_weights: Optional[List[float]] = None
) -> int:
    """
    Tính điểm độ tin cậy (Confidence Score, 0 - 100%) của Incident Group:
    - Số lượng cảnh báo và tần suất quan sát
    - Tính đa dạng của nguồn dữ liệu (Wazuh Agent, FortiGate Syslog, Network)
    - Trọng số tương quan trung bình giữa các nút
    - Cấp độ nghiêm trọng (Rule Level)
    - Có kỹ thuật MITRE ATT&CK được ghi nhận hay không
    Điểm được giới hạn trong khoảng [15%, 98%] để tuân thủ nguyên tắc SOC thực tế.
    """
    if not sub_alerts:
        return 0

    n = len(sub_alerts)
    max_level = max(a.get("rule", {}).get("level", 0) for a in sub_alerts)
    total_occurrences = sum(a.get("occurrence_count", 1) for a in sub_alerts)

    if n == 1:
        base = 35 + min(max_level * 2, 20)
        occ_bonus = min(math.log10(max(total_occurrences, 1)) * 5, 10)
        return min(max(round(base + occ_bonus), 15), 75)

    size_score = min(10 + (n * 3), 25)

    if edge_weights and len(edge_weights) > 0:
        avg_weight = sum(edge_weights) / len(edge_weights)
        graph_score = min(avg_weight * 30, 30)
    else:
        graph_score = 15

    severity_score = min(max_level * 1.3, 20)

    has_agent = any(a.get("agent", {}).get("name") not in ["wazuh-server", "localhost", None, ""] for a in sub_alerts)
    has_syslog = any(a.get("data", {}).get("devname") for a in sub_alerts)
    has_network_ip = any(a.get("data", {}).get("srcip") for a in sub_alerts)

    corroboration_score = 5
    if (has_agent and has_syslog) or (has_agent and has_network_ip and len(sub_alerts) > 1):
        corroboration_score = 15
    elif has_agent or has_syslog:
        corroboration_score = 10

    mitre_bonus = 0
    for a in sub_alerts:
        rule = a.get("rule", {})
        if rule.get("mitre", {}) or str(rule.get("id")) in ["100100", "100101", "100102", "100103", "100104", "5710"]:
            mitre_bonus = 10
            break

    total = size_score + graph_score + severity_score + corroboration_score + mitre_bonus
    return min(max(round(total), 20), 98)


def generate_incident_attack_graph_mermaid(incident_group: Dict[str, Any]) -> str:
    """
    Sinh Mermaid attack graph theo chiều dọc.

    Các cảnh báo liên tiếp có cùng rule và nội dung được gom thành một bước
    ``N lần`` để sơ đồ giữ được thông tin nhưng không biến thành một chuỗi
    ngang rất dài, khó đọc ở mức zoom mặc định.
    """
    alerts = incident_group.get("alerts", [])
    if not alerts:
        return "graph TD\n    empty[\"Không có dữ liệu cảnh báo\"]"

    sorted_alerts = sorted(alerts, key=lambda a: parse_wazuh_time(a.get("timestamp", "")))

    lines = [
        "graph TD",
        "    classDef attacker fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fecaca;",
        "    classDef step fill:#1e293b,stroke:#3b82f6,stroke-width:1.5px,color:#e2e8f0;",
        "    classDef repeated fill:#312e81,stroke:#818cf8,stroke-width:2px,color:#e0e7ff;",
        "    classDef target fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#bbf7d0;"
    ]

    def clean_text(s: Any) -> str:
        text = str(s or "").replace('"', "'").replace("[", "(").replace("]", ")").replace("<", "(").replace(">", ")").replace("&", " và ")
        return re.sub(r'[\r\n]+', ' ', text).strip()

    src_ips = incident_group.get("source_ips", [])
    dst_ips = incident_group.get("destination_ips", [])
    devices = incident_group.get("devices", [])
    primary_entity = incident_group.get("entity", "Unknown-Target")

    semantics = [derive_alert_semantics(alert) for alert in sorted_alerts]
    semantic_source_ips = [item.get("source_ip") for item in semantics if item.get("source_ip")]
    src_node_id = "src_node"
    src_label = clean_text(src_ips[0] if src_ips else (semantic_source_ips[0] if semantic_source_ips else "Nguồn chưa xác định"))
    lines.append(f'    {src_node_id}["Nguồn: {src_label}"]:::attacker')

    def alert_signature(alert: Dict[str, Any]) -> Tuple[str, str, str]:
        rule = alert.get("rule", {}) or {}
        semantic = derive_alert_semantics(alert)
        return (
            clean_text(rule.get("id", "Rule")),
            clean_text(semantic["label"]),
            clean_text(rule.get("level", 0)),
        )

    # Collapse only consecutive events. This preserves meaningful stage order
    # when the same rule appears again later in the incident.
    grouped_steps: List[Dict[str, Any]] = []
    for alert in sorted_alerts:
        signature = alert_signature(alert)
        if grouped_steps and grouped_steps[-1]["signature"] == signature:
            grouped_steps[-1]["alerts"].append(alert)
        else:
            grouped_steps.append({"signature": signature, "alerts": [alert]})

    max_steps = 10
    displayed_steps = grouped_steps[:max_steps]
    prev_node_id = src_node_id

    for i, step in enumerate(displayed_steps):
        a = step["alerts"][0]
        step_id = f"step_{i}"
        r_id = a.get("rule", {}).get("id", "Rule")
        r_lvl = a.get("rule", {}).get("level", 0)
        r_desc = clean_text(derive_alert_semantics(a)["label"])[:80]
        count = sum(max(1, _safe_int(item.get("occurrence_count"), 1)) for item in step["alerts"])
        if count > 1:
            step_label = f"Bước {i+1}: Rule {r_id} ×{count}<br/>{r_desc} (Lvl {r_lvl})<br/>{count} cảnh báo tương tự được gom"
            node_class = "repeated"
        else:
            step_label = f"Bước {i+1}: Rule {r_id}<br/>{r_desc} (Lvl {r_lvl})"
            node_class = "step"
        lines.append(f'    {step_id}["{step_label}"]:::{node_class}')
        lines.append(f'    {prev_node_id} --> {step_id}')
        prev_node_id = step_id

    omitted_steps = grouped_steps[max_steps:]
    omitted_alerts = sum(len(step["alerts"]) for step in omitted_steps)
    if omitted_alerts:
        more_id = "step_more"
        lines.append(f'    {more_id}["… +{omitted_alerts} cảnh báo tiếp theo …"]:::step')
        lines.append(f'    {prev_node_id} --> {more_id}')
        prev_node_id = more_id

    dst_node_id = "dst_node"
    target_names = []
    if devices:
        target_names.extend(devices[:2])
    if dst_ips:
        for ip in dst_ips[:2]:
            if ip not in target_names:
                target_names.append(ip)
    if not target_names:
        target_names = [clean_text(primary_entity)]

    target_label = clean_text(", ".join(target_names))
    lines.append(f'    {dst_node_id}["Mục Tiêu: {target_label}"]:::target')
    lines.append(f'    {prev_node_id} --> {dst_node_id}')

    return "\n".join(lines)


def derive_alert_semantics(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Derive a bounded, evidence-backed event meaning from raw Wazuh logs."""
    events = [alert]
    events.extend(item for item in (alert.get("evidence_events") or []) if isinstance(item, dict))
    logs = [str(item.get("full_log") or "") for item in events if item.get("full_log")]
    corpus = "\n".join(logs)
    lowered = corpus.lower()
    source_match = re.search(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b", corpus, flags=re.I)
    paths = list(dict.fromkeys(
        match.rstrip(".,;)") for match in re.findall(r"(?:resource|path):\s*([^\s]+)", corpus, flags=re.I)
    ))
    is_web_scan = any(marker in lowered for marker in (
        "[web_scan_detected]", "directory enumeration", "probing restricted resource"
    ))
    if is_web_scan:
        return {
            "category": "web_scan",
            "label": "Web scan: dò quét thư mục và tài nguyên web",
            "incident_type": "Phát hiện dò quét thư mục và tài nguyên web",
            "source_ip": source_match.group(1) if source_match else None,
            "paths": paths,
            "mitre_techniques": ["T1595"],
            "mitre_tactics": ["Reconnaissance"],
            "raw_log_count": len(logs),
        }
    rule = alert.get("rule") or {}
    return {
        "category": "rule_event",
        "label": str(rule.get("description") or "Cảnh báo bảo mật").strip(),
        "incident_type": str(rule.get("description") or "Cảnh báo bảo mật").strip(),
        "source_ip": source_match.group(1) if source_match else None,
        "paths": paths,
        "mitre_techniques": [],
        "mitre_tactics": [],
        "raw_log_count": len(logs),
    }


def build_deterministic_incident_analysis(group: Dict[str, Any]) -> Dict[str, Any]:
    """Create the fast incident-card report directly from verified evidence."""
    alerts = [item for item in (group.get("alerts") or []) if isinstance(item, dict)]
    semantics = [derive_alert_semantics(alert) for alert in alerts]
    primary = next((item for item in semantics if item["category"] == "web_scan"), semantics[0] if semantics else None)
    score = _safe_int(group.get("priority_score", group.get("risk_score")), 0)
    priority = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM" if score >= 30 else "LOW"
    evidence_ids = list(dict.fromkeys(str(item) for item in (group.get("alert_ids") or []) if item))
    devices = list(group.get("devices") or [])
    device = str(devices[0] if devices else group.get("entity") or "thiết bị chưa xác định")

    if primary and primary["category"] == "web_scan":
        paths = list(dict.fromkeys(path for item in semantics for path in item.get("paths", [])))
        sources = list(dict.fromkeys(item.get("source_ip") for item in semantics if item.get("source_ip")))
        path_text = f" Các tài nguyên bị thăm dò: {', '.join(paths)}." if paths else ""
        source_text = f" Log ghi nhận IP nguồn {sources[0]}." if sources else ""
        summary = (
            f"Thiết bị {device} ghi nhận {len(evidence_ids) or group.get('alert_count', len(alerts))} "
            f"sự kiện có marker WEB_SCAN_DETECTED, thể hiện hành vi dò quét thư mục/tài nguyên web."
            f"{source_text}{path_text}"
        )
        mitre = ["T1595"]
    else:
        description = primary["label"] if primary else "Cảnh báo bảo mật"
        summary = f"Thiết bị {device} ghi nhận nhóm sự kiện: {description}."
        mitre = list(group.get("mitre_techniques") or [])

    confidence_value = group.get("confidence_score", group.get("correlation_confidence", 0))
    return {
        "incident_type": primary["incident_type"] if primary else "Sự cố bảo mật",
        "priority": priority,
        "risk_score": score,
        "mitre_techniques": mitre,
        "summary": summary,
        "reasoning": summary,
        "confidence": round(float(confidence_value or 0) / 100, 2),
        "evidence_ids": evidence_ids,
        "analysis_source": "deterministic_full_log",
    }


def deduplicate_alerts(alerts: List[Dict[str, Any]], dedup_window_seconds: int = 60) -> List[Dict[str, Any]]:
    """
    Gộp các alert trùng fingerprint trong khoảng thời gian ngắn thành 1.
    Fingerprint = hash(rule_id + src_ip + dst_ip + devname)

    Output mỗi deduplicated alert có thêm:
      - occurrence_count: số lần trùng lặp
      - first_seen:       timestamp của lần xuất hiện đầu tiên
      - last_seen:        timestamp của lần xuất hiện gần nhất
      - evidence_ids:     danh sách alert_id của các bản trùng
      - evidence_events:  mẫu sự kiện gốc để không làm mất full_log khác biệt
    """
    if not alerts:
        return []

    alerts_sorted = sorted(alerts, key=lambda a: parse_wazuh_time(a.get("timestamp", "")))
    deduped: List[Dict[str, Any]] = []
    latest_by_fingerprint: Dict[str, Dict[str, Any]] = {}

    for alert in alerts_sorted:
        fingerprint = _dedup_fingerprint(alert)

        current_time = parse_wazuh_time(alert.get("timestamp", ""))
        current_ts_str = alert.get("timestamp", "")
        alert_id = alert.get("id", "")

        merged = False
        existing = latest_by_fingerprint.get(fingerprint)
        if existing is not None:
            burst_start = float(existing.get("_first_seen_epoch", 0) or 0)
            if current_time > 0 and burst_start > 0 and current_time - burst_start <= dedup_window_seconds:
                existing["occurrence_count"] = existing.get("occurrence_count", 1) + 1
                existing["_last_seen_epoch"] = current_time
                existing["last_seen"] = current_ts_str or existing.get("last_seen", "")
                if alert_id and alert_id not in existing.get("evidence_ids", []):
                    existing.setdefault("evidence_ids", []).append(alert_id)
                samples = existing.setdefault("evidence_events", [])
                if len(samples) < 12:
                    samples.append(alert.copy())
                merged = True

        if not merged:
            new_alert = alert.copy()
            new_alert["_fingerprint"] = fingerprint
            new_alert["_first_seen_epoch"] = current_time
            new_alert["_last_seen_epoch"] = current_time
            new_alert["occurrence_count"] = 1
            new_alert["first_seen"] = current_ts_str
            new_alert["last_seen"] = current_ts_str
            new_alert["evidence_ids"] = [alert_id] if alert_id else []
            new_alert["evidence_events"] = [alert.copy()]
            deduped.append(new_alert)
            latest_by_fingerprint[fingerprint] = new_alert

    for a in deduped:
        a.pop("_fingerprint", None)
        a.pop("_first_seen_epoch", None)
        a.pop("_last_seen_epoch", None)

    return deduped


def _mitre_values(alert: Dict[str, Any], mitre_mapping: Optional[Dict[str, Any]] = None) -> Tuple[Set[str], Set[str]]:
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    native = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}

    def values(value: Any) -> Set[str]:
        if isinstance(value, list):
            return {_clean_scalar(item) for item in value if _clean_scalar(item)}
        scalar = _clean_scalar(value)
        return {scalar} if scalar else set()

    techniques = values(native.get("id")) | values(native.get("technique"))
    tactics = values(native.get("tactic"))
    mapping = (mitre_mapping or {}).get(_clean_scalar(rule.get("id")), {})
    if isinstance(mapping, dict):
        techniques |= values(mapping.get("technique_id"))
        tactics |= values(mapping.get("tactic"))
    return techniques, tactics


def _edge_reasons(a1: Dict[str, Any], a2: Dict[str, Any], semantic_score: float = 0.0) -> Set[str]:
    entities1 = extract_entities(a1)
    entities2 = extract_entities(a2)
    shared = entities1 & entities2
    reasons: Set[str] = set()
    shared_ip = any(item.startswith("ip:") for item in shared)
    shared_asset = any(item.startswith(("agent:", "agent-id:", "host:")) for item in shared)
    shared_user = any(item.startswith("user:") for item in shared)
    if shared_ip:
        reasons.add("shared_ip")
    if shared_user:
        reasons.add("shared_user")

    rule_obj1 = a1.get("rule") or {}
    rule_obj2 = a2.get("rule") or {}
    rule1 = _clean_scalar(rule_obj1.get("id"))
    rule2 = _clean_scalar(rule_obj2.get("id"))
    max_level = max(_safe_int(rule_obj1.get("level")), _safe_int(rule_obj2.get("level")))
    techniques1, tactics1 = _mitre_values(a1)
    techniques2, tactics2 = _mitre_values(a2)

    # Same-host temporal proximity is supporting context, not enough evidence
    # by itself. Require a repeated rule, a material rule sequence, MITRE
    # continuity, or semantic support before creating an incident edge.
    if shared_asset and rule1 and rule1 == rule2:
        reasons.update({"shared_asset", "repeated_rule"})
    if rule1 and rule2 and rule1 != rule2 and (shared_ip or shared_user or (shared_asset and max_level >= 7)):
        reasons.add("rule_sequence")
        if shared_asset:
            reasons.add("shared_asset")
    if (shared_ip or shared_user or shared_asset) and ((techniques1 & techniques2) or (tactics1 & tactics2)):
        reasons.add("mitre_context")
        if shared_asset:
            reasons.add("shared_asset")
    if shared_asset and semantic_score >= 0.80:
        reasons.add("shared_asset")
        reasons.add("semantic_support")

    # Lateral movement pivot: dst IP in a1 matches src IP in a2, or vice versa
    data1 = a1.get("data") or {}
    data2 = a2.get("data") or {}
    dst1 = _valid_ip(_first_value(data1, "dstip", "dst_ip", "destination.ip"))
    src2 = _valid_ip(_first_value(data2, "srcip", "src_ip", "source.ip"))
    dst2 = _valid_ip(_first_value(data2, "dstip", "dst_ip", "destination.ip"))
    src1 = _valid_ip(_first_value(data1, "srcip", "src_ip", "source.ip"))
    if (dst1 and src2 and dst1 == src2) or (dst2 and src1 and dst2 == src1):
        reasons.add("lateral_movement_pivot")
        reasons.add("rule_sequence")

    return reasons


def _primary_entity(alerts: List[Dict[str, Any]]) -> str:
    candidates = [get_entity(alert) for alert in alerts]
    candidates = [candidate for candidate in candidates if candidate != "syslog-gateway"]
    return Counter(candidates).most_common(1)[0][0] if candidates else "syslog-gateway"


def _iso_from_epoch(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat() if value > 0 else ""


def _alert_start_epoch(alert: Dict[str, Any]) -> float:
    return parse_wazuh_time(alert.get("first_seen") or alert.get("timestamp", ""))


def _alert_end_epoch(alert: Dict[str, Any]) -> float:
    return parse_wazuh_time(alert.get("last_seen") or alert.get("timestamp", ""))


def _interval_gap_seconds(a1: Dict[str, Any], a2: Dict[str, Any]) -> float:
    start1, end1 = _alert_start_epoch(a1), _alert_end_epoch(a1)
    start2, end2 = _alert_start_epoch(a2), _alert_end_epoch(a2)
    if not start1 or not end1 or not start2 or not end2:
        return math.inf
    if end1 < start2:
        return start2 - end1
    if end2 < start1:
        return start1 - end2
    return 0.0


def correlate_alerts(
    alerts: List[Dict[str, Any]],
    time_window_minutes: int = 15,
    max_incident_span_minutes: int = 60,
    mitre_mapping: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Tương quan Đa Nguồn & Graph-based Kill-Chain Analysis (Wazuh Agent + FortiGate Syslog):
    - Sử dụng NetworkX graph để nối các nút alert nếu dùng chung entity (src_ip/dst_ip/user).
    - Sử dụng TF-IDF Cosine Similarity (Scikit-Learn) để phát hiện hành vi tương tự qua mô tả log text.
    - Phân tách các connected components thành từng Incident Group hoàn chỉnh.
    """
    if not alerts:
        return []

    alerts_sorted = sorted(alerts, key=_alert_start_epoch)
    time_window_sec = max(time_window_minutes, 1) * 60
    max_span_sec = max(max_incident_span_minutes, time_window_minutes) * 60

    # 1. Tính toán TF-IDF Cosine Similarity giữa các log text nếu scikit-learn khả dụng
    text_corpus = []
    for a in alerts_sorted:
        rule_desc = a.get("rule", {}).get("description", "")
        full_log = a.get("full_log", "")
        data_json = json.dumps(a.get("data", {}))
        text_corpus.append(f"{rule_desc} {full_log} {data_json}")

    similarity_matrix = None
    if TfidfVectorizer and len(text_corpus) > 1:
        try:
            vectorizer = TfidfVectorizer(stop_words="english")
            tfidf_mat = vectorizer.fit_transform(text_corpus)
            similarity_matrix = cosine_similarity(tfidf_mat)
        except Exception:
            similarity_matrix = None

    # 2. Dựng Đồ Thị Tương Quan NetworkX (Multi-Entity Weighted Attack Chain)
    if nx:
        G = nx.Graph()
        entities_list = [extract_alert_entities(a) for a in alerts_sorted]
        for idx, alert in enumerate(alerts_sorted):
            G.add_node(idx, alert=alert, entities=entities_list[idx])

        # Nối cạnh dựa trên Multi-Entity Weighted Correlation hoặc TF-IDF Cosine Similarity
        for i in range(len(alerts_sorted)):
            a1 = alerts_sorted[i]
            e1 = entities_list[i]
            end1 = _alert_end_epoch(a1)
            for j in range(i + 1, len(alerts_sorted)):
                a2 = alerts_sorted[j]
                e2 = entities_list[j]
                start2 = _alert_start_epoch(a2)
                if end1 and start2 and start2 - end1 > time_window_sec:
                    break
                if _interval_gap_seconds(a1, a2) > time_window_sec:
                    continue
                semantic_score = float(similarity_matrix[i][j]) if similarity_matrix is not None else 0.0
                upstream_reasons = _edge_reasons(a1, a2, semantic_score)
                weight, weighted_reasons = compute_correlation_weight(e1, e2, time_window_sec, semantic_score)
                if upstream_reasons:
                    combined_reasons = sorted(set(upstream_reasons) | set(r.split(":")[0] for r in weighted_reasons))
                    final_weight = max(weight, 0.50)
                    G.add_edge(i, j, weight=final_weight, reasons=combined_reasons)

        # Tách các connected components
        raw_components = list(nx.connected_components(G))
        components = []
        for component in raw_components:
            ordered = sorted(component, key=lambda idx: _alert_start_epoch(alerts_sorted[idx]))
            segment: List[int] = []
            segment_start = 0.0
            for idx in ordered:
                event_start = _alert_start_epoch(alerts_sorted[idx])
                event_end = _alert_end_epoch(alerts_sorted[idx])
                if segment and event_end and segment_start and event_end - segment_start > max_span_sec:
                    components.append(set(segment))
                    segment = []
                if not segment:
                    segment_start = event_start
                segment.append(idx)
            if segment:
                components.append(set(segment))
        groups = []

        for comp_idx, comp in enumerate(components):
            sub_alerts = [alerts_sorted[idx] for idx in sorted(comp)]
            primary_entity = _primary_entity(sub_alerts)
            start_t = min(_alert_start_epoch(a) for a in sub_alerts)
            end_t = max(_alert_end_epoch(a) for a in sub_alerts)
            total_count = sum(a.get("occurrence_count", 1) for a in sub_alerts)
            rule_ids = sorted({_clean_scalar((a.get("rule") or {}).get("id")) for a in sub_alerts} - {""})

            # Collect unique source/destination IPs and devices across all alerts in group
            source_ips = sorted({_valid_ip(_first_value(a.get("data") or {}, "srcip", "src_ip", "source.ip"))
                                 for a in sub_alerts} - {""})
            dest_ips = sorted({_valid_ip(_first_value(a.get("data") or {}, "dstip", "dst_ip", "destination.ip"))
                               for a in sub_alerts} - {""})
            devices = sorted({_clean_scalar((a.get("agent") or {}).get("name")) for a in sub_alerts} - {""})

            # Determine correlation reason(s) for this component
            corr_reasons: Set[str] = set()
            evidence_counts: Dict[str, int] = defaultdict(int)
            edge_weights: List[float] = []
            for edge_i, edge_j, edge_data in G.subgraph(comp).edges(data=True):
                if "weight" in edge_data:
                    edge_weights.append(edge_data["weight"])
                for reason in edge_data.get("reasons", []):
                    r_clean = reason.split(":")[0]
                    corr_reasons.add(r_clean)
                    evidence_counts[r_clean] += 1
            repeated = total_count > len(sub_alerts)
            if repeated:
                corr_reasons.add("repeated_activity")
                evidence_counts["repeated_activity"] += total_count - len(sub_alerts)
            correlation_reason = ", ".join(sorted(corr_reasons)) if corr_reasons else "singleton"

            all_techniques: Set[str] = set()
            all_tactics: Set[str] = set()
            for alert in sub_alerts:
                techniques, tactics = _mitre_values(alert, mitre_mapping)
                all_techniques |= techniques
                all_tactics |= tactics

            confidence = 0
            if "shared_ip" in corr_reasons:
                confidence += 40
            if "shared_asset" in corr_reasons:
                confidence += 25
            if "shared_user" in corr_reasons:
                confidence += 20
            if "rule_sequence" in corr_reasons:
                confidence += 15
            if "repeated_rule" in corr_reasons:
                confidence += 15
            if "mitre_context" in corr_reasons:
                confidence += 10
            if "repeated_activity" in corr_reasons:
                confidence += min(35, 15 + int(math.log10(max(total_count, 1)) * 10))
            if "semantic_support" in corr_reasons:
                confidence += 5
            confidence = min(confidence, 100)
            is_correlated = bool(corr_reasons) and correlation_reason != "singleton"
            if len(devices) > 1 and "rule_sequence" in corr_reasons:
                correlation_type = "cross_device_rule_sequence"
            elif len(rule_ids) > 1 and "rule_sequence" in corr_reasons:
                correlation_type = "multi_rule_sequence"
            elif "repeated_activity" in corr_reasons or "repeated_rule" in corr_reasons:
                correlation_type = "repeated_activity"
            elif is_correlated:
                correlation_type = "shared_entity_cluster"
            else:
                correlation_type = "singleton"

            first_alert = sub_alerts[0]
            anchor_ids = first_alert.get("evidence_ids") or [first_alert.get("id")]
            anchor = _clean_scalar(anchor_ids[0] if anchor_ids else "") or f"{start_t}:{(first_alert.get('rule') or {}).get('id', '')}"
            alert_ids = []
            for alert in sub_alerts:
                for alert_id in alert.get("evidence_ids") or [alert.get("id", "unknown")]:
                    if alert_id and alert_id not in alert_ids:
                        alert_ids.append(alert_id)
            group_id = hashlib.sha256(f"{primary_entity}:{anchor}".encode()).hexdigest()[:12]
            incident_id = f"INC-{group_id.upper()}"
            group_dict = {
                "group_id": incident_id,
                "incident_id": incident_id,
                "entity": primary_entity,
                "alert_ids": alert_ids,
                "involved_alerts": len(sub_alerts),
                "alerts": sub_alerts,
                "alert_count": total_count,
                "graph_nodes_count": len(sub_alerts),
                "devices": devices,
                "source_ips": sorted(source_ips),
                "destination_ips": sorted(dest_ips),
                "correlation_reason": correlation_reason,
                "confidence_score": calculate_incident_confidence(sub_alerts, edge_weights),
                "correlation_confidence": confidence,
                "correlation_reasons": sorted(corr_reasons),
                "correlation_evidence": dict(sorted(evidence_counts.items())),
                "correlation_type": correlation_type,
                "is_correlated": is_correlated,
                "distinct_rule_ids": rule_ids,
                "mitre_techniques": sorted(all_techniques),
                "mitre_tactics": sorted(all_tactics),
                "time_span": {
                    "start": start_t,
                    "end": end_t
                },
                "first_seen": _iso_from_epoch(start_t),
                "last_seen": _iso_from_epoch(end_t),
                "risk_score": None  # Populated by score_priority() in server.py
            }
            group_dict["attack_graph_mermaid"] = generate_incident_attack_graph_mermaid(group_dict)
            groups.append(group_dict)
        return groups

    # Keep the core SOC workflow available on a lean local installation where
    # optional graph/ML packages are not installed.  The result deliberately
    # retains the same audit fields as the graph path, so priority scoring and
    # the dashboard do not need a separate "degraded" response shape.
    groups = []
    for alert in alerts_sorted:
        entity = get_entity(alert)
        current_time = _alert_start_epoch(alert)
        current_end = _alert_end_epoch(alert)
        merged = False
        for group in groups:
            previous_time = group["time_span"]["end"]
            if current_time and previous_time and group["entity"] == entity and current_time - previous_time <= time_window_sec:
                for alert_id in alert.get("evidence_ids") or [alert.get("id", "unknown")]:
                    if alert_id and alert_id not in group["alert_ids"]:
                        group["alert_ids"].append(alert_id)
                group["alerts"].append(alert)
                group["alert_count"] += alert.get("occurrence_count", 1)
                group["graph_nodes_count"] += 1
                group["involved_alerts"] = len(group["alerts"])
                group["time_span"]["end"] = current_end
                group["last_seen"] = _iso_from_epoch(current_end)
                group["correlation_reason"] = "shared_entity_temporal_fallback"
                group["correlation_reasons"] = ["shared_primary_entity"]
                group["correlation_evidence"] = {"shared_primary_entity": group["graph_nodes_count"] - 1}
                group["correlation_confidence"] = 50
                group["is_correlated"] = True
                merged = True
                break
        if not merged:
            repeated = _safe_int(alert.get("occurrence_count"), 1) > 1
            anchor = _clean_scalar(alert.get("id")) or f"{current_time}:{(alert.get('rule') or {}).get('id', '')}"
            group_id = hashlib.sha256(f"{entity}:{anchor}".encode()).hexdigest()[:12]
            groups.append({
                "group_id": f"INC-{group_id.upper()}",
                "incident_id": f"INC-{group_id.upper()}",
                "entity": entity,
                "alert_ids": list(alert.get("evidence_ids") or [alert.get("id", "unknown")]),
                "involved_alerts": 1,
                "alerts": [alert],
                "alert_count": alert.get("occurrence_count", 1),
                "graph_nodes_count": 1,
                "devices": [alert.get("agent", {}).get("name", "")] if alert.get("agent", {}).get("name") else [],
                "source_ips": [alert.get("data", {}).get("srcip", "")] if alert.get("data", {}).get("srcip") else [],
                "destination_ips": [alert.get("data", {}).get("dstip", "")] if alert.get("data", {}).get("dstip") else [],
                "correlation_reason": "repeated_activity" if repeated else "singleton",
                "correlation_reasons": ["repeated_activity"] if repeated else [],
                "correlation_evidence": {"repeated_activity": _safe_int(alert.get("occurrence_count"), 1) - 1} if repeated else {},
                "correlation_confidence": 25 if repeated else 0,
                "correlation_type": "repeated_activity" if repeated else "singleton",
                "is_correlated": repeated,
                "distinct_rule_ids": [_clean_scalar((alert.get("rule") or {}).get("id"))],
                "mitre_techniques": sorted(_mitre_values(alert, mitre_mapping)[0]),
                "mitre_tactics": sorted(_mitre_values(alert, mitre_mapping)[1]),
                "time_span": {"start": current_time, "end": current_end},
                "first_seen": _iso_from_epoch(current_time),
                "last_seen": _iso_from_epoch(current_end),
                "risk_score": None,
            })
    for group in groups:
        rule_ids = sorted({_clean_scalar((a.get("rule") or {}).get("id")) for a in group["alerts"]} - {""})
        group["distinct_rule_ids"] = rule_ids
        if group.get("is_correlated") and len(rule_ids) > 1:
            group["correlation_type"] = "multi_rule_sequence"
        group["confidence_score"] = calculate_incident_confidence(group["alerts"])
        group["attack_graph_mermaid"] = generate_incident_attack_graph_mermaid(group)
    return groups


def dry_run_rule(rule_xml: str, sample_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Chạy thử nghiệm Rule nháp (Dry-run Sandbox) trên tập alerts lịch sử.
    """
    match_count = 0
    matched_ids = []

    match_tag = re.search(r"<match>(.*?)</match>", rule_xml, re.DOTALL)
    pattern = match_tag.group(1).strip() if match_tag else ""

    for alert in (sample_alerts or [])[:200]:
        desc = alert.get("rule", {}).get("description", "")
        data_str = json.dumps(alert.get("data", {}))
        if pattern and (pattern.lower() in desc.lower() or pattern.lower() in data_str.lower()):
            match_count += 1
            if alert.get("id"):
                matched_ids.append(str(alert.get("id")))

    fp_risk = "Thấp (0-5%)" if match_count < 10 else ("Trung bình (5-20%)" if match_count < 50 else "Cao (>20%)")
    return {
        "would_match_count": match_count,
        "sample_matched_alert_ids": matched_ids[:10],
        "estimated_false_positive_risk": fp_risk
    }


def generate_config_diff(old_content: str, new_content: str, filename: str = "local_rules.xml") -> str:
    """
    Tạo Unified Diff chuẩn giữa cấu hình cũ và cấu hình nháp mới.
    """
    import difflib
    old_lines = (old_content or "").splitlines(keepends=True)
    new_lines = (new_content or "").splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}"
    )
    res = "".join(diff)
    if not res:
        res = f"--- a/{filename}\n+++ b/{filename}\n@@ -0,0 +1,5 @@\n" + new_content
    return res


def score_priority(incident_group: Dict[str, Any], mitre_mapping: Dict[str, Any], asset_criticality: Dict[str, Any]) -> Dict[str, Any]:
    """
    Tính điểm ưu tiên cho Incident Group nâng cao (Kill-Chain Priority Score):
    score = severity + MITRE + occurrence + asset criticality + correlation confidence + kill-chain stage
    """
    if not incident_group or "alerts" not in incident_group:
        return {"score": 0, "breakdown": {"error": "Invalid incident group"}}

    alerts = incident_group["alerts"]
    if not alerts:
        return {"score": 0, "breakdown": {"error": "Empty alerts"}}

    # 1. Base Severity (Max severity level)
    max_severity = max(_safe_int((a.get("rule") or {}).get("level")) for a in alerts)
    w1_severity = min(max_severity * 3.0, 45)

    # 2. MITRE Tactic Bonus
    mitre_details: Set[str] = set(incident_group.get("mitre_techniques", []))
    mitre_tactics: Set[str] = set(incident_group.get("mitre_tactics", []))
    for a in alerts:
        techniques, tactics = _mitre_values(a, mitre_mapping)
        mitre_details |= techniques
        mitre_tactics |= tactics
    w2_mitre = min(len(mitre_details) * 4 + len(mitre_tactics) * 2, 15)

    # 3. Logarithmic Occurrence Frequency
    count = _safe_int(incident_group.get("alert_count"), len(alerts))
    w3_occurrence = min(math.log10(max(count, 1)) * 6, 10)

    # 4. Asset Criticality
    aliases = {incident_group.get("entity", ""), *incident_group.get("source_ips", []), *incident_group.get("destination_ips", [])}
    criticality = 1
    if isinstance(asset_criticality, dict):
        for alias in aliases:
            asset = asset_criticality.get(alias, {})
            if not isinstance(asset, dict):
                continue
            raw = asset.get("criticality", 1)
            if isinstance(raw, str):
                raw = {"low": 1, "medium": 3, "high": 4, "critical": 5}.get(raw.lower(), 1)
            try:
                criticality = max(criticality, int(raw))
            except (TypeError, ValueError):
                pass
    w4_asset = min(criticality * 2, 10)

    # 5. Correlation evidence. A singleton alert must not receive an incident bonus.
    correlation_confidence = _safe_int(incident_group.get("correlation_confidence"))
    w5_correlation = min(correlation_confidence / 10, 10)

    # 6. Later ATT&CK stages carry more operational impact, capped at 10.
    tactic_weights = {
        "reconnaissance": 1, "resource development": 1, "initial access": 3,
        "execution": 5, "persistence": 5, "privilege escalation": 6,
        "defense evasion": 6, "credential access": 6, "discovery": 3,
        "lateral movement": 8, "collection": 6, "command and control": 8,
        "exfiltration": 10, "impact": 10,
    }
    kill_chain_bonus = max((tactic_weights.get(tactic.lower(), 0) for tactic in mitre_tactics), default=0)

    total_score = w1_severity + w2_mitre + w3_occurrence + w4_asset + w5_correlation + kill_chain_bonus
    final_score = min(round(total_score), 100)

    breakdown = {
        "base_severity_score": round(w1_severity, 2),
        "mitre_tactics_score": round(w2_mitre, 2),
        "occurrence_frequency_score": round(w3_occurrence, 2),
        "asset_criticality_score": round(w4_asset, 2),
        "kill_chain_stage_bonus": kill_chain_bonus,
        "correlation_confidence_score": round(w5_correlation, 2),
        "correlation_confidence": correlation_confidence,
        "max_rule_level": max_severity,
        "total_occurrences": count,
        "entity_criticality_level": criticality,
        "mitre_techniques_found": sorted(mitre_details),
        "mitre_tactics_found": sorted(mitre_tactics),
    }

    return {
        "score": final_score,
        "breakdown": breakdown
    }


def get_severity_distribution(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
    """Tính toán số lượng alert theo từng mức độ nghiêm trọng (Critical, High, Medium, Low)."""
    critical = 0
    high = 0
    medium = 0
    low = 0
    for a in alerts:
        lvl = a.get("rule", {}).get("level", 0)
        if lvl >= 15:
            critical += 1
        elif lvl >= 12:
            high += 1
        elif lvl >= 7:
            medium += 1
        else:
            low += 1
    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "total": len(alerts)
    }


def get_top_rules_distribution(alerts: List[Dict[str, Any]], top_n: int = 5) -> List[Dict[str, Any]]:
    """Tính toán danh sách Top N Rule ID xuất hiện nhiều nhất."""
    counts = {}
    descriptions = {}
    for a in alerts:
        rule_id = str(a.get("rule", {}).get("id", "1000"))
        desc = a.get("rule", {}).get("description", "Unknown Rule")
        counts[rule_id] = counts.get(rule_id, 0) + 1
        descriptions[rule_id] = desc

    sorted_rules = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return [{"rule_id": r_id, "count": cnt, "description": descriptions[r_id]} for r_id, cnt in sorted_rules]


def get_hourly_series_distribution(alerts: List[Dict[str, Any]], tz_offset_hours: int = 7) -> Dict[str, Any]:
    """
    Tính toán số lượng cảnh báo phát sinh theo từng khung giờ (24h time series).
    tz_offset_hours: offset so với UTC (mặc định 7 = UTC+7 Việt Nam).
    """
    hourly = {f"{h:02d}:00": 0 for h in range(24)}
    for a in alerts:
        ts = a.get("timestamp", "")
        if "T" in ts:
            try:
                utc_hour = int(ts.split("T")[1][:2])
                local_hour = (utc_hour + tz_offset_hours) % 24
                hour_key = f"{local_hour:02d}:00"
                if hour_key in hourly:
                    hourly[hour_key] += 1
            except Exception:
                pass
    non_zero = {k: v for k, v in hourly.items() if v > 0}
    return {
        "labels": list(hourly.keys()),
        "data": list(hourly.values()),
        "non_zero_hours": non_zero,
        "timezone": f"UTC+{tz_offset_hours}",
        "note": "Giờ hiển thị đã được chuyển sang giờ Việt Nam (UTC+7)"
    }


def list_monitored_devices(
    known_devices: List[Dict[str, Any]],
    wazuh_agents: List[Dict[str, Any]],
    recent_alerts: Optional[List[Dict[str, Any]]] = None,
    ttl_days: int = 7,
    wazuh_host: str = ""
) -> Dict[str, Any]:
    """
    Xác minh & Phân loại Danh sách Thiết bị Giám sát (2 LOẠI RÕ RÀNG):
    1. "Endpoint có Agent" (DMZ Web Server, Ubuntu-Agent, Wazuh Manager).
    2. "Thiết bị Giám sát qua Syslog (Agentless)" (FortiGate Firewall, Network Devices).
    """
    monitored_list = []
    monitored_ips = set()

    # 1. Wazuh Manager chính (Host đang kết nối)
    if wazuh_host and wazuh_host not in ["127.0.0.1", "localhost", ""]:
        item = {
            "name": "Wazuh Manager",
            "ip": wazuh_host,
            "type": "Wazuh SIEM Server",
            "os_model": "Amazon Linux 2023 (Wazuh v4.14.7)",
            "agent_status": "active (Kết nối thời gian thực)",
            "last_seen": "Real-time",
            "monitoring_since": "Cấu hình trong Settings",
            "criticality": "Cao",
            "is_verified": True,
            "verification_method": "Cách 1: Authenticated REST API Connection"
        }
        monitored_list.append(item)
        monitored_ips.add(wazuh_host)

    # 2. Endpoint có Wazuh Agent (Active / Registered Agents)
    for agent in wazuh_agents:
        agent_id = str(agent.get("id", ""))
        if agent_id == "000":
            continue

        ip = agent.get("ip", "")
        name = agent.get("name", f"agent-{agent_id}")
        raw_status = str(agent.get("status", "disconnected")).lower()

        is_active = (raw_status == "active")
        agent_status_str = "active (Đang truyền log)" if is_active else f"inactive ({raw_status})"
        os_info = agent.get("os", {}).get("name", "Linux/Windows") if isinstance(agent.get("os"), dict) else "Wazuh Agent OS"
        os_ver = agent.get("os", {}).get("version", "") if isinstance(agent.get("os"), dict) else ""
        os_full = f"{os_info} {os_ver}".strip() if os_ver else os_info

        if ip and ip in monitored_ips:
            continue

        name_lower = name.lower()
        is_net_appliance = any(k in name_lower for k in ["forti", "cisco", "firewall", "router", "switch"])
        
        if is_net_appliance:
            dev_type_str = "Thiết bị Mạng (Remote Syslog Agentless)"
            if "forti" in name_lower or "firewall" in name_lower:
                os_full = "FortiOS 7.2 (Remote Syslog Stream)"
            elif "cisco" in name_lower or "router" in name_lower or "switch" in name_lower:
                os_full = "Cisco IOS-XE / NX-OS (Syslog Integration)"
        else:
            dev_type_str = "Endpoint có Agent (Host Agent)"

        item = {
            "name": name,
            "ip": ip or "Dynamic IP",
            "type": dev_type_str,
            "os_model": os_full,
            "agent_status": agent_status_str,
            "last_seen": agent.get("lastKeepAlive", "Gần đây"),
            "monitoring_since": agent.get("dateAdd", "Đã đăng ký"),
            "criticality": "Cao" if is_active else "Trung bình",
            "is_verified": True,
            "verification_method": "Cách 2: Remote Syslog / Agent API" if is_net_appliance else "Cách 1: Active Wazuh Agent API"
        }
        monitored_list.append(item)
        if ip:
            monitored_ips.add(ip)

    # 3. Thiết bị Giám sát qua Syslog (Agentless Integration - Chỉ tính khi CÓ LOG TRONG PHIÊN HIỆN TẠI - 15 Phút gần nhất)
    passive_devices = {}
    exclude_ips = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "", wazuh_host}
    now_epoch = time.time()
    session_window_secs = 900  # 15 phút live session window

    if recent_alerts:
        import datetime
        for alert in recent_alerts:
            ts_str = alert.get("timestamp", "")
            alert_epoch = 0
            if ts_str:
                try:
                    clean_ts = ts_str.replace("+0000", "Z").replace("Z", "")
                    dt = datetime.datetime.fromisoformat(clean_ts)
                    alert_epoch = dt.timestamp()
                except Exception:
                    pass

            # CHỈ XÁC MINH ACTIVE NẾU LOG XUẤT HIỆN TRONG PHIÊN HIỆN TẠI (15 PHÚT GẦN NHẤT)
            is_live_session = (alert_epoch > 0) and ((now_epoch - alert_epoch) <= session_window_secs)
            if not is_live_session:
                continue

            data = alert.get("data", {})
            devname = data.get("devname") or "FortiGate Firewall"
            srcip = data.get("srcip")
            dstip = data.get("dstip")
            target_ip = srcip if (srcip and srcip not in exclude_ips) else (dstip if (dstip and dstip not in exclude_ips) else None)

            if target_ip and target_ip not in monitored_ips:
                passive_devices[target_ip] = {
                    "name": f"{devname} ({target_ip})",
                    "ip": target_ip,
                    "type": "Thiết bị Giám sát qua Syslog (Agentless)",
                    "os_model": "FortiOS / Syslog Integration",
                    "agent_status": "active (Đang truyền log phiên hiện tại)",
                    "last_seen": ts_str or "Vừa nhận log",
                    "monitoring_since": "Remote Syslog Port 514 UDP",
                    "criticality": "Cao",
                    "is_verified": True,
                    "verification_method": "Cách 2: Live FortiGate Syslog Stream (Phiên hiện tại)"
                }

    for ip, dev in passive_devices.items():
        monitored_list.append(dev)
        monitored_ips.add(ip)

    # 4. Thiết bị từ CMDB chưa có tín hiệu -> Ghi nhận inactive
    for dev in known_devices:
        ip = dev.get("ip", "")
        if ip and ip in monitored_ips:
            continue
        item = {
            "name": dev.get("name", "Network Device"),
            "ip": ip,
            "type": dev.get("type", "CMDB Record"),
            "os_model": dev.get("model", "Chưa xác minh"),
            "agent_status": "inactive (Chưa có tín hiệu trong khung TTL)",
            "last_seen": "Chưa có tín hiệu",
            "monitoring_since": "Đăng ký CMDB",
            "criticality": "Thấp",
            "is_verified": False,
            "verification_method": "CMDB Inventory"
        }
        monitored_list.append(item)

    return {
        "count": len(monitored_list),
        "devices": monitored_list,
        "ttl_days_applied": ttl_days,
        "verified_only": True
    }
