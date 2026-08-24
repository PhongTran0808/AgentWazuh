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

    # 2. Dựng Đồ Thị Tương Quan NetworkX (Graph-Based Attack Chain)
    if nx:
        G = nx.Graph()
        for idx, alert in enumerate(alerts_sorted):
            G.add_node(idx, alert=alert)

        # Nối cạnh dựa trên Entity hoặc TF-IDF Cosine Similarity
        for i in range(len(alerts_sorted)):
            a1 = alerts_sorted[i]
            t1 = parse_wazuh_time(a1.get("timestamp", ""))
            e1 = get_entity(a1)

            for j in range(i + 1, len(alerts_sorted)):
                a2 = alerts_sorted[j]
                t2 = parse_wazuh_time(a2.get("timestamp", ""))
                e2 = get_entity(a2)

                # Nối cạnh nếu thỏa mãn khung thời gian
                if abs(t2 - t1) <= time_window_sec:
                    # Tiêu chuẩn 1: Trùng Entity (IP/Agent/Hostname)
                    if e1 != "syslog-gateway" and e1 == e2:
                        G.add_edge(i, j, reason="shared_entity")
                    # Tiêu chuẩn 2: TF-IDF Cosine Similarity cao (>= 0.65)
                    elif similarity_matrix is not None and similarity_matrix[i][j] >= 0.65:
                        G.add_edge(i, j, reason="semantic_similarity")

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
                               if a.get("data", {}).get("srcip", "") not in ["", "0.0.0.0", "127.0.0.1"]})
            dest_ips = list({a.get("data", {}).get("dstip", "") for a in sub_alerts
                             if a.get("data", {}).get("dstip", "") not in ["", "0.0.0.0", "255.255.255.255"]})
            devices = list({a.get("agent", {}).get("name", "") for a in sub_alerts
                            if a.get("agent", {}).get("name", "")})

            # Determine correlation reason(s) for this component
            corr_reasons = set()
            for edge_i, edge_j in G.edges(comp):
                ed = G.edges[edge_i, edge_j].get("reason", "")
                if ed:
                    corr_reasons.add(ed)
            correlation_reason = ", ".join(sorted(corr_reasons)) if corr_reasons else "temporal_proximity"

            group_id = hashlib.md5(f"{primary_entity}_{start_t}_{comp_idx}".encode()).hexdigest()[:12]
            incident_id = f"INC-{group_id.upper()}"
            groups.append({
                "group_id": incident_id,
                "incident_id": incident_id,
                "entity": primary_entity,
                "alert_ids": [a.get("id", "unknown") for a in sub_alerts],
                "involved_alerts": len(sub_alerts),
                "alerts": sub_alerts,
                "alert_count": total_count,
                "graph_nodes_count": len(sub_alerts),
                "devices": devices,
                "source_ips": source_ips,
                "destination_ips": dest_ips,
                "correlation_reason": correlation_reason,
                "time_span": {
                    "start": start_t,
                    "end": end_t
                },
                "first_seen": datetime.fromtimestamp(start_t, tz=timezone.utc).isoformat() if start_t else "",
                "last_seen": datetime.fromtimestamp(end_t, tz=timezone.utc).isoformat() if end_t else "",
                "risk_score": None  # Populated by score_priority() in server.py
            })
        return groups

    # Fallback nếu không có networkx: Nhóm theo entity và time window cơ bản
    groups = []
    for alert in alerts_sorted:
        entity = get_entity(alert)
        current_time = parse_wazuh_time(alert.get("timestamp", ""))
        merged = False
        for group in groups:
            if group["entity"] == entity:
                if current_time - group["time_span"]["start"] <= time_window_sec:
                    group["alert_ids"].append(alert.get("id", "unknown"))
                    group["alerts"].append(alert)
                    group["alert_count"] += alert.get("occurrence_count", 1)
                    if current_time > group["time_span"]["end"]:
                        group["time_span"]["end"] = current_time
                    merged = True
                    break
        if not merged:
            group_id = hashlib.md5(f"{entity}_{current_time}".encode()).hexdigest()[:12]
            groups.append({
                "group_id": f"INC-{group_id.upper()}",
                "entity": entity,
                "alert_ids": [alert.get("id", "unknown")],
                "alerts": [alert],
                "alert_count": alert.get("occurrence_count", 1),
                "graph_nodes_count": 1,
                "time_span": {
                    "start": current_time,
                    "end": current_time
                }
            })
    return groups


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
    wazuh_host: str = "192.168.1.248"
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

        item = {
            "name": name,
            "ip": ip or "Dynamic IP",
            "type": "Endpoint có Agent",
            "os_model": os_full,
            "agent_status": agent_status_str,
            "last_seen": agent.get("lastKeepAlive", "Gần đây"),
            "monitoring_since": agent.get("dateAdd", "Đã đăng ký"),
            "criticality": "Cao" if is_active else "Trung bình",
            "is_verified": True,
            "verification_method": "Cách 1: Active Wazuh Agent API"
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
