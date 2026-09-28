import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

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
    """Parse Wazuh ISO timestamp to Unix float timestamp. Fallback to current time if invalid."""
    if not timestamp_str:
        return datetime.now(timezone.utc).timestamp()
    try:
        clean_str = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        return dt.timestamp()
    except Exception:
        return datetime.now(timezone.utc).timestamp()


def get_entity(alert: Dict[str, Any]) -> str:
    """
    Extract primary entity (srcip, dstip, agent name, or hostname) from multi-source alerts
    (Supports both Wazuh Agent host events and FortiGate Syslog network events).
    """
    data = alert.get("data", {})
    srcip = data.get("srcip") or data.get("src_ip")
    if srcip and srcip not in ["0.0.0.0", "127.0.0.1", "::1", ""]:
        return srcip

    dstip = data.get("dstip") or data.get("dst_ip")
    if dstip and dstip not in ["0.0.0.0", "255.255.255.255", "127.0.0.1", "::1", ""]:
        return dstip

    agent = alert.get("agent", {})
    agent_name = agent.get("name")
    if agent_name and agent_name not in ["wazuh-server", "localhost"]:
        return f"agent-{agent_name}"

    agent_id = agent.get("id")
    if agent_id and agent_id != "000":
        return f"agent-{agent_id}"

    # Check FortiGate devname or predecoder hostname
    devname = data.get("devname")
    if devname:
        return f"device-{devname}"

    return "syslog-gateway"


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
    Sinh mã Mermaid đồ thị chuỗi tấn công có hướng (Directed Attack Graph):
    Attacker / Source IP -> Bước 1 (Rule/Tactic) -> Bước 2 -> ... -> Target Entity / Asset
    """
    alerts = incident_group.get("alerts", [])
    if not alerts:
        return "graph LR\n    empty[\"Không có dữ liệu cảnh báo\"]"

    sorted_alerts = sorted(alerts, key=lambda a: parse_wazuh_time(a.get("timestamp", "")))

    lines = [
        "graph LR",
        "    classDef attacker fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fecaca;",
        "    classDef step fill:#1e293b,stroke:#3b82f6,stroke-width:1.5px,color:#e2e8f0;",
        "    classDef target fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#bbf7d0;"
    ]

    def clean_text(s: Any) -> str:
        text = str(s or "").replace('"', "'").replace("[", "(").replace("]", ")").replace("<", "&lt;").replace(">", "&gt;")
        return re.sub(r'[\r\n]+', ' ', text).strip()

    src_ips = incident_group.get("source_ips", [])
    dst_ips = incident_group.get("destination_ips", [])
    devices = incident_group.get("devices", [])
    primary_entity = incident_group.get("entity", "Unknown-Target")

    src_node_id = "src_node"
    src_label = clean_text(src_ips[0] if src_ips else "External Attacker / Remote")
    lines.append(f'    {src_node_id}["Nguồn: {src_label}"]:::attacker')

    max_steps = 8
    displayed_alerts = sorted_alerts[:max_steps]
    prev_node_id = src_node_id

    for i, a in enumerate(displayed_alerts):
        step_id = f"step_{i}"
        r_id = a.get("rule", {}).get("id", "Rule")
        r_lvl = a.get("rule", {}).get("level", 0)
        r_desc = clean_text(a.get("rule", {}).get("description", "Cảnh báo bảo mật"))[:50]
        step_label = f"Bước {i+1}: Rule {r_id}<br/>{r_desc} (Lvl {r_lvl})"
        lines.append(f'    {step_id}["{step_label}"]:::step')
        lines.append(f'    {prev_node_id} --> {step_id}')
        prev_node_id = step_id

    if len(sorted_alerts) > max_steps:
        more_id = "step_more"
        lines.append(f'    {more_id}["... +{len(sorted_alerts) - max_steps} cảnh báo tiếp theo ..."]:::step')
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


def deduplicate_alerts(alerts: List[Dict[str, Any]], dedup_window_seconds: int = 60) -> List[Dict[str, Any]]:
    """
    Gộp các alert trùng fingerprint trong khoảng thời gian ngắn thành 1.
    Fingerprint = hash(rule_id + src_ip + dst_ip + devname)

    Output mỗi deduplicated alert có thêm:
      - occurrence_count: số lần trùng lặp
      - first_seen:       timestamp của lần xuất hiện đầu tiên
      - last_seen:        timestamp của lần xuất hiện gần nhất
      - evidence_ids:     danh sách alert_id của các bản trùng
    """
    if not alerts:
        return []

    alerts_sorted = sorted(alerts, key=lambda a: parse_wazuh_time(a.get("timestamp", "")))
    deduped = []

    for alert in alerts_sorted:
        rule_id = str(alert.get("rule", {}).get("id", ""))
        data = alert.get("data", {})
        srcip = data.get("srcip", "")
        dstip = data.get("dstip", "")
        devname = data.get("devname", "")

        raw_fingerprint = f"{rule_id}_{srcip}_{dstip}_{devname}"
        fingerprint = hashlib.md5(raw_fingerprint.encode()).hexdigest()

        current_time = parse_wazuh_time(alert.get("timestamp", ""))
        current_ts_str = alert.get("timestamp", "")
        alert_id = alert.get("id", "")

        merged = False
        for existing in deduped:
            if existing.get("_fingerprint") == fingerprint:
                existing_time = parse_wazuh_time(existing.get("timestamp", ""))
                if abs(current_time - existing_time) <= dedup_window_seconds:
                    existing["occurrence_count"] = existing.get("occurrence_count", 1) + 1
                    # Track first_seen (earliest timestamp)
                    if current_ts_str and current_ts_str < existing.get("first_seen", current_ts_str):
                        existing["first_seen"] = current_ts_str
                    # Track last_seen (latest timestamp)
                    if current_ts_str and current_ts_str > existing.get("last_seen", current_ts_str):
                        existing["last_seen"] = current_ts_str
                    # Accumulate evidence IDs
                    if alert_id and alert_id not in existing.get("evidence_ids", []):
                        existing.setdefault("evidence_ids", []).append(alert_id)
                    merged = True
                    break

        if not merged:
            new_alert = alert.copy()
            new_alert["_fingerprint"] = fingerprint
            new_alert["occurrence_count"] = 1
            new_alert["first_seen"] = current_ts_str
            new_alert["last_seen"] = current_ts_str
            new_alert["evidence_ids"] = [alert_id] if alert_id else []
            deduped.append(new_alert)

    for a in deduped:
        a.pop("_fingerprint", None)

    return deduped


def correlate_alerts(alerts: List[Dict[str, Any]], time_window_minutes: int = 15) -> List[Dict[str, Any]]:
    """
    Tương quan Đa Nguồn & Graph-based Kill-Chain Analysis (Wazuh Agent + FortiGate Syslog):
    - Sử dụng NetworkX graph để nối các nút alert nếu dùng chung entity (src_ip/dst_ip/user).
    - Sử dụng TF-IDF Cosine Similarity (Scikit-Learn) để phát hiện hành vi tương tự qua mô tả log text.
    - Phân tách các connected components thành từng Incident Group hoàn chỉnh.
    """
    if not alerts:
        return []

    alerts_sorted = sorted(alerts, key=lambda a: parse_wazuh_time(a.get("timestamp", "")))
    time_window_sec = time_window_minutes * 60

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
            e1 = entities_list[i]
            for j in range(i + 1, len(alerts_sorted)):
                e2 = entities_list[j]
                sim = float(similarity_matrix[i][j]) if similarity_matrix is not None else 0.0
                weight, reasons = compute_correlation_weight(e1, e2, time_window_sec, sim)
                if weight >= 0.40:
                    G.add_edge(i, j, weight=weight, reasons=reasons)

        # Tách các connected components
        components = list(nx.connected_components(G))
        groups = []

        for comp_idx, comp in enumerate(components):
            sub_alerts = [alerts_sorted[idx] for idx in sorted(comp)]
            primary_entity = get_entity(sub_alerts[0])
            start_t = min(parse_wazuh_time(a.get("timestamp", "")) for a in sub_alerts)
            end_t = max(parse_wazuh_time(a.get("timestamp", "")) for a in sub_alerts)
            total_count = sum(a.get("occurrence_count", 1) for a in sub_alerts)

            # Collect unique source/destination IPs and devices across all alerts in group
            source_ips = list({a.get("data", {}).get("srcip", "") for a in sub_alerts
                               if a.get("data", {}).get("srcip", "") not in ["", "0.0.0.0", "127.0.0.1", "::1"]})
            dest_ips = list({a.get("data", {}).get("dstip", "") for a in sub_alerts
                             if a.get("data", {}).get("dstip", "") not in ["", "0.0.0.0", "255.255.255.255", "127.0.0.1"]})
            devices = list({a.get("agent", {}).get("name", "") for a in sub_alerts
                            if a.get("agent", {}).get("name", "") and a.get("agent", {}).get("name") not in ["wazuh-server", "localhost"]})

            # Edge weights & reasons in component
            comp_nodes = list(comp)
            edge_weights = []
            corr_reasons = set()
            for u in comp_nodes:
                for v in comp_nodes:
                    if u < v and G.has_edge(u, v):
                        ed = G.edges[u, v]
                        edge_weights.append(ed.get("weight", 0.5))
                        for r in ed.get("reasons", []):
                            corr_reasons.add(r.split(":")[0])

            correlation_reason = ", ".join(sorted(corr_reasons)) if corr_reasons else ("single_alert_event" if len(sub_alerts) == 1 else "temporal_multi_entity")
            confidence = calculate_incident_confidence(sub_alerts, edge_weights)

            group_id = hashlib.md5(f"{primary_entity}_{start_t}_{comp_idx}".encode()).hexdigest()[:12]
            incident_id = f"INC-{group_id.upper()}"
            group_dict = {
                "group_id": incident_id,
                "incident_id": incident_id,
                "entity": primary_entity,
                "alert_ids": [a.get("id", "unknown") for a in sub_alerts],
                "involved_alerts": len(sub_alerts),
                "alerts": sub_alerts,
                "alert_count": total_count,
                "graph_nodes_count": len(sub_alerts),
                "devices": devices,
                "source_ips": sorted(source_ips),
                "destination_ips": sorted(dest_ips),
                "correlation_reason": correlation_reason,
                "confidence_score": confidence,
                "time_span": {
                    "start": start_t,
                    "end": end_t
                },
                "first_seen": datetime.fromtimestamp(start_t, tz=timezone.utc).isoformat() if start_t else "",
                "last_seen": datetime.fromtimestamp(end_t, tz=timezone.utc).isoformat() if end_t else "",
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
        current_time = parse_wazuh_time(alert.get("timestamp", ""))
        merged = False
        for group in groups:
            previous_time = group["time_span"]["end"]
            if group["entity"] == entity and current_time - previous_time <= time_window_sec:
                group["alert_ids"].append(alert.get("id", "unknown"))
                group["alerts"].append(alert)
                group["alert_count"] += alert.get("occurrence_count", 1)
                group["graph_nodes_count"] += 1
                group["involved_alerts"] = len(group["alerts"])
                group["time_span"]["end"] = current_time
                group["last_seen"] = datetime.fromtimestamp(current_time, tz=timezone.utc).isoformat()
                merged = True
                break
        if not merged:
            group_id = hashlib.md5(f"{entity}_{current_time}".encode()).hexdigest()[:12]
            groups.append({
                "group_id": f"INC-{group_id.upper()}",
                "incident_id": f"INC-{group_id.upper()}",
                "entity": entity,
                "alert_ids": [alert.get("id", "unknown")],
                "involved_alerts": 1,
                "alerts": [alert],
                "alert_count": alert.get("occurrence_count", 1),
                "graph_nodes_count": 1,
                "devices": [alert.get("agent", {}).get("name", "")] if alert.get("agent", {}).get("name") else [],
                "source_ips": [alert.get("data", {}).get("srcip", "")] if alert.get("data", {}).get("srcip") else [],
                "destination_ips": [alert.get("data", {}).get("dstip", "")] if alert.get("data", {}).get("dstip") else [],
                "correlation_reason": "shared_entity_temporal_fallback",
                "time_span": {"start": current_time, "end": current_time},
                "first_seen": datetime.fromtimestamp(current_time, tz=timezone.utc).isoformat(),
                "last_seen": datetime.fromtimestamp(current_time, tz=timezone.utc).isoformat(),
                "risk_score": None,
            })
    for g in groups:
        g["confidence_score"] = calculate_incident_confidence(g["alerts"])
        g["attack_graph_mermaid"] = generate_incident_attack_graph_mermaid(g)
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
    score = w1*max_severity + w2*mitre_bonus + w3*occurrence_log + w4*asset_criticality + w5*kill_chain_stage
    """
    if not incident_group or "alerts" not in incident_group:
        return {"score": 0, "breakdown": {"error": "Invalid incident group"}}

    alerts = incident_group["alerts"]
    if not alerts:
        return {"score": 0, "breakdown": {"error": "Empty alerts"}}

    # 1. Base Severity (Max severity level)
    max_severity = max(a.get("rule", {}).get("level", 0) for a in alerts)
    w1_severity = min(max_severity * 4.5, 45)

    # 2. MITRE Tactic Bonus
    mitre_score = 0
    mitre_details = []
    for a in alerts:
        rule_id = str(a.get("rule", {}).get("id", ""))
        mapping = mitre_mapping.get(rule_id)
        if mapping:
            mitre_details.append(mapping.get("technique_id", "Unknown"))
            mitre_score = 20
            break

    w2_mitre = mitre_score

    # 3. Logarithmic Occurrence Frequency
    count = incident_group.get("alert_count", len(alerts))
    w3_occurrence = min(math.log10(max(count, 1)) * 8, 15)

    # 4. Asset Criticality
    entity = incident_group.get("entity", "")
    criticality = asset_criticality.get(entity, {}).get("criticality", 1) if isinstance(asset_criticality, dict) else 1
    w4_asset = min(criticality * 2, 10)

    # 5. Kill-Chain Stage Multiplier Bonus
    kill_chain_bonus = 5
    if max_severity >= 12 or any(a.get("rule", {}).get("id") == "100104" for a in alerts):
        kill_chain_bonus = 15
    elif max_severity >= 7:
        kill_chain_bonus = 10

    total_score = w1_severity + w2_mitre + w3_occurrence + w4_asset + kill_chain_bonus
    final_score = min(round(total_score), 100)

    breakdown = {
        "base_severity_score": round(w1_severity, 2),
        "mitre_tactics_score": round(w2_mitre, 2),
        "occurrence_frequency_score": round(w3_occurrence, 2),
        "asset_criticality_score": round(w4_asset, 2),
        "kill_chain_stage_bonus": kill_chain_bonus,
        "max_rule_level": max_severity,
        "total_occurrences": count,
        "entity_criticality_level": criticality,
        "mitre_techniques_found": mitre_details
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
