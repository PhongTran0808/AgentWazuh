"""
Intelligent Wazuh Rule Generator Pipeline for AgentWazuh.
Integrates RAG docs, live wazuh-logtest verification, AI reasoning, syntax checking, and diff generation.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree

import requests

from integrations.wazuh_config_manager import (
    WazuhConfigError,
    _read_target as read_wazuh_config_target,
    merge_rule_group,
)
from services.correlation_engine import generate_config_diff
from services.wazuh_logtest_service import generate_canonical_sample_log, test_log_event
from services.wazuh_rag_service import (
    get_next_free_rule_id,
    search_docs,
    search_local,
)

logger = logging.getLogger("RuleGenerator")

OMNIROUTE_BASE_URL = os.getenv("OMNIROUTE_BASE_URL", "http://localhost:20128/v1")
OMNIROUTE_API_KEY = os.getenv("OMNIROUTE_API_KEY", "")


def _extract_intent_parameters(query: str) -> Dict[str, Any]:
    text = (query or "").strip()
    lowered = text.lower()

    freq_match = re.search(r"\b(\d+)\s*(?:lần|lan|times?|attempts?)\b", lowered)
    time_match = re.search(r"\b(\d+)\s*(?:giây|giay|s|seconds?)\b", lowered)
    level_match = re.search(r"\blevel\s*(\d{1,2})\b", lowered)

    frequency = int(freq_match.group(1)) if freq_match else 5
    timeframe = int(time_match.group(1)) if time_match else 60
    level = int(level_match.group(1)) if level_match else (12 if any(w in lowered for w in ["critical", "nghiêm trọng", "khẩn"]) else 10)

    # MITRE ATT&CK and Group determination
    mitre_id = "T1110"
    group_name = "custom_rules"
    scenario = "Generic Security Event"
    pattern = ""

    if "ssh" in lowered or "sshd" in lowered:
        mitre_id = "T1110.001"
        group_name = "sshd,authentication_failures"
        scenario = "SSH Brute Force"
        pattern = "Failed password"
    elif "ftp" in lowered or "vsftpd" in lowered:
        mitre_id = "T1110"
        group_name = "vsftpd,authentication_failures"
        scenario = "FTP Brute Force"
        pattern = "FAIL LOGIN"
    elif "rdp" in lowered or "4625" in lowered or "windows" in lowered:
        mitre_id = "T1110"
        group_name = "windows,authentication_failures"
        scenario = "Windows RDP / Logon Failure Brute Force"
        pattern = "4625"
    elif any(k in lowered for k in ["web", "apache", "nginx", "http", "403", "401"]):
        if "sqli" in lowered:
            mitre_id = "T1190"
            group_name = "web,web_attack"
            scenario = "Web SQL Injection Attack"
            pattern = "UNION SELECT"
        elif "dir" in lowered or "scan" in lowered:
            mitre_id = "T1595.001"
            group_name = "web,web_attack"
            scenario = "Web Directory Enumeration"
            pattern = "Kali-Audit"
        elif "dos" in lowered or "flood" in lowered:
            mitre_id = "T1498"
            group_name = "web,web_attack"
            scenario = "HTTP Connection Flood / DoS"
            pattern = "Connection Flood"
        else:
            mitre_id = "T1110"
            group_name = "web,web_attack"
            scenario = "Web Authentication Brute Force"
            pattern = "authentication failure"
    elif "sudo" in lowered or re.search(r"\bsu\b", lowered):
        mitre_id = "T1548.003"
        group_name = "sudo,privilege_escalation"
        scenario = "Sudo Privilege Escalation Failure"
        pattern = "authentication failure"
    else:
        req_clean = re.sub(
            r"^(?:hãy\s+|vui lòng\s+)?(?:tạo|viết|thêm|sửa)\s+(?:một\s+)?rule\s*",
            "", text, flags=re.IGNORECASE,
        ).strip(" .:-")
        scenario = req_clean[:60] or "Custom Detection Event"
        pattern = scenario

    return {
        "scenario": scenario,
        "frequency": max(1, frequency),
        "timeframe": max(1, timeframe),
        "level": min(16, max(1, level)),
        "mitre_id": mitre_id,
        "group_name": group_name,
        "pattern": pattern,
        "rule_name": f"Phát hiện {scenario} ({frequency} lần trong {timeframe}s)"
    }


def _try_llm_synthesis(
    query: str,
    rag_context: str,
    base_rule_id: int,
    next_rule_id: int,
    sample_log: str,
    logtest_summary: str,
    params: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Attempt to refine reasoning & XML via Omniroute local LLM.
    """
    try:
        headers = {
            "Authorization": f"Bearer {OMNIROUTE_API_KEY}",
            "Content-Type": "application/json"
        }
        headers.pop("Authorization", None)
        if OMNIROUTE_API_KEY:
            headers["Authorization"] = f"Bearer {OMNIROUTE_API_KEY}"
        system_prompt = (
            "You are an expert Wazuh SIEM Detection Engineer. Your task is to generate a valid, compliant "
            "Wazuh 4.14 XML detection rule based on ground-truth wazuh-logtest output and RAG documentation.\n"
            "RULES:\n"
            "1. frequency and timeframe MUST be attributes of the <rule> tag: <rule id=\"...\" level=\"...\" frequency=\"...\" timeframe=\"...\">\n"
            "2. When frequency/timeframe are used, MUST use <if_matched_sid>parent_id</if_matched_sid>. Never use <if_sid> with frequency/timeframe!\n"
            "3. Use <same_source_ip /> to correlate events by source IP.\n"
            "4. Return a valid JSON object with keys: 'rule_xml', 'rule_name', 'explanation', 'mitre_id'."
        )
        user_prompt = (
            f"User Request: {query}\n"
            f"Available Next Rule ID: {next_rule_id}\n"
            f"Ground-Truth Base Rule ID from wazuh-logtest: {base_rule_id}\n"
            f"Ground-Truth Logtest Summary: {logtest_summary}\n"
            f"Sample Log: {sample_log}\n"
            f"Parameters: frequency={params['frequency']}, timeframe={params['timeframe']}, level={params['level']}, group={params['group_name']}\n"
            f"RAG Syntax Docs Snippet:\n{rag_context[:800]}\n\n"
            "Generate JSON response only."
        )

        resp = requests.post(
            f"{OMNIROUTE_BASE_URL}/chat/completions",
            json={
                "model": os.getenv("OMNIROUTE_MODEL", "auto/best-reasoning"),
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.1,
                "max_tokens": 1000
            },
            headers=headers,
            timeout=8
        )
        if resp.status_code == 200:
            content = resp.json()["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            if parsed.get("rule_xml"):
                root = ElementTree.fromstring(parsed["rule_xml"])
                rules = root.findall(".//rule") if root.tag == "group" else []
                if len(rules) == 1 and rules[0].get("id") == str(next_rule_id):
                    if (
                        rules[0].get("frequency") == str(params["frequency"])
                        and rules[0].get("timeframe") == str(params["timeframe"])
                        and rules[0].findtext("if_matched_sid") == str(base_rule_id)
                        and rules[0].find("match") is not None
                    ):
                        return parsed
    except Exception as exc:
        logger.info("Omniroute synthesis skipped or failed (%s), using expert deterministic synthesis", exc)
    return None


def generate_rule_proposal(
    query: str,
    sample_log_override: Optional[str] = None,
    etc_dir: str = "/var/ossec/etc"
) -> Dict[str, Any]:
    """
    Main Pipeline:
    1. Parse user query parameters.
    2. Retrieve RAG documentation and local rules.
    3. Run wazuh-logtest with canonical log to discover real base rule ID and decoder.
    4. Synthesize compliant Wazuh 4.14 XML.
    5. Validate XML syntax and build unified diff with local_rules.xml.
    6. Return complete package with reasoning, pre-filled form values, test results, and diff.
    """
    # 1. Parse intent
    params = _extract_intent_parameters(query)

    # 2. RAG Knowledge
    rag_docs = search_docs(query, k=3)
    local_rules_docs = search_local(query, k=3)
    next_rule_id = get_next_free_rule_id(etc_dir)

    # 3. Logtest Ground-Truth
    sample_log = sample_log_override or generate_canonical_sample_log(query)
    logtest_report = test_log_event(sample_log)
    base_rule_id = logtest_report.get("matched_rule_id")
    if not logtest_report.get("ok") or not base_rule_id:
        detail = logtest_report.get("summary") or logtest_report.get("message") or "no matching parent rule"
        raise WazuhConfigError(
            f"Không thể xác minh rule cha bằng wazuh-logtest cho log mẫu; "
            f"không tạo rule tương quan dựa trên ID phỏng đoán. Kết quả: {detail}"
        )

    # 4. Synthesize XML
    llm_res = _try_llm_synthesis(
        query=query,
        rag_context=rag_docs,
        base_rule_id=base_rule_id,
        next_rule_id=next_rule_id,
        sample_log=sample_log,
        logtest_summary=logtest_report.get("summary", ""),
        params=params
    )

    if llm_res and llm_res.get("rule_xml"):
        rule_xml = llm_res["rule_xml"].strip()
        rule_name = llm_res.get("rule_name", params["rule_name"])
        explanation = llm_res.get("explanation", "")
        mitre_id = llm_res.get("mitre_id", params["mitre_id"])
    else:
        # Deterministic Expert Rule Synthesis (100% Wazuh 4.14 Compliant)
        rule_name = params["rule_name"]
        mitre_id = params["mitre_id"]
        group_name = params["group_name"]
        freq = params["frequency"]
        timeframe = params["timeframe"]
        level = params["level"]

        group = ElementTree.Element("group", {"name": f"{group_name},"})
        rule = ElementTree.SubElement(group, "rule", {
            "id": str(next_rule_id),
            "level": str(level),
            "frequency": str(freq),
            "timeframe": str(timeframe),
        })
        ElementTree.SubElement(rule, "if_matched_sid").text = str(base_rule_id)
        ElementTree.SubElement(rule, "same_source_ip")
        ElementTree.SubElement(rule, "match").text = params["pattern"]
        ElementTree.SubElement(rule, "description").text = rule_name
        mitre = ElementTree.SubElement(rule, "mitre")
        ElementTree.SubElement(mitre, "id").text = mitre_id
        ElementTree.SubElement(rule, "group").text = "authentication_failures,custom_detection,"
        rule_xml = ElementTree.tostring(group, encoding="unicode")
        explanation = (
            f"Quy tắc được thiết lập với ngưỡng tương quan thời gian (`frequency={freq}`, `timeframe={timeframe}s`) "
            f"kế thừa từ Rule cha ID `{base_rule_id}` (được xác thực trực tiếp qua kiểm thử `wazuh-logtest`). "
            f"Sử dụng điều kiện `<same_source_ip />` để gom nhóm các lần thất bại từ cùng một địa chỉ IP nguồn, "
            f"tránh tình trạng cảnh báo rác (False Positive) từ nhiều nguồn phân tán."
        )

    # 5. Pre-flight Validation & Diff
    _, current_rules_xml = read_wazuh_config_target("rules")
    merged_xml, _ = merge_rule_group(current_rules_xml, rule_xml)
    unified_diff = generate_config_diff(current_rules_xml, merged_xml, "local_rules.xml")

    # 6. Format Detailed Reasoning & Evidence
    reasoning_markdown = f"""### 🛡️ Đề Xuất Quy Tắc Wazuh: `{rule_name}`

Hệ thống AgentWazuh đã tiến hành khảo sát cơ sở tri thức (RAG) và kiểm thử thực nghiệm bằng `wazuh-logtest` cho yêu cầu: **"{query}"**.

#### 1. 🔍 Khảo Sát Ground-Truth & Kiểm Thử `wazuh-logtest`
- **Dòng log kiểm thử thực tế**:
  ```text
  {sample_log}
  ```
- **Kết quả phân tích 3 pha của Wazuh Engine**:
  * **Phase 1 (Pre-decoding)**: `{logtest_report.get('parsed', {}).get('phase1', {}).get('program_name', 'N/A')}`
  * **Phase 2 (Decoding)**: Decoder `{logtest_report.get('decoder_name') or 'N/A'}` | Source IP: `{logtest_report.get('parsed', {}).get('phase2', {}).get('srcip', 'N/A')}`
  * **Phase 3 (Rule Matching)**: Khớp Rule cha **ID `{base_rule_id}`** (Level {logtest_report.get('parsed', {}).get('phase3', {}).get('level', 'N/A')}) - *{logtest_report.get('parsed', {}).get('phase3', {}).get('description', 'N/A')}*.
- **Rule cha đã xác minh**: `<if_matched_sid>{base_rule_id}</if_matched_sid>`.
- **Giải thích từ AI:** {explanation or 'Không sử dụng LLM; nội dung được xác định từ logtest và RAG.'}

#### 2. 📖 Căn Cứ Cú Pháp Wazuh 4.14 (RAG Knowledge)
- Theo chuẩn tài liệu Wazuh 4.14, các quy tắc tương quan ngưỡng (Correlation Windows) bắt buộc khai báo `frequency` và `timeframe` dưới dạng **thuộc tính** trên thẻ `<rule>`, không sử dụng thẻ con.
- Bắt buộc dùng `<if_matched_sid>` kết hợp với `<same_source_ip />` để tránh cảnh báo sai.
- Cấp phát ID mới: `{next_rule_id}` (thuộc dải custom an toàn `100000-120000`).
- Ánh xạ kỹ thuật MITRE ATT&CK: **`{mitre_id}`**.
"""

    return {
        "status": "success",
        "rule_id": next_rule_id,
        "rule_name": rule_name,
        "level": params["level"],
        "frequency": params["frequency"],
        "timeframe": params["timeframe"],
        "match_pattern": params["pattern"] or f"if_matched_sid {base_rule_id}",
        "parent_rule_id": base_rule_id,
        "group_name": params["group_name"],
        "mitre_id": mitre_id,
        "draft_xml": rule_xml,
        "unified_diff": unified_diff,
        "sample_log": sample_log,
        "logtest_report": logtest_report,
        "reasoning_markdown": reasoning_markdown,
        "rag_evidence": rag_docs[:1000],
        "local_rule_evidence": local_rules_docs[:1000],
    }
