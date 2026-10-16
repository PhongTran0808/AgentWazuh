"""
Wazuh Logtest Service for AgentWazuh.
Provides live log verification and decoder/parent-rule discovery using `/var/ossec/bin/wazuh-logtest`.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict

from integrations.wazuh_config_manager import run_logtest_check

logger = logging.getLogger("WazuhLogtestService")


def generate_canonical_sample_log(query: str) -> str:
    """
    Extract raw log line if user provided one, or generate a realistic canonical log line
    representative of the target attack scenario.
    """
    text = (query or "").strip()
    lowered = text.lower()

    # If the user included a full log line in the prompt (e.g., quotes or syslog format)
    log_match = re.search(r"[`'\"]([A-Z][a-z]{2}\s+\d+[\s\S]*?)[`'\"]", text)
    if log_match:
        return log_match.group(1).strip()

    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
    target_ip = ip_match.group(1) if ip_match else "192.168.1.100"

    if "ssh" in lowered or "sshd" in lowered:
        return f"Oct 16 12:00:00 server sshd[1234]: Failed password for invalid user admin from {target_ip} port 22 ssh2"
    elif "ftp" in lowered or "vsftpd" in lowered:
        return f"Oct 16 12:00:00 server vsftpd[5432]: FAIL LOGIN: Client \"{target_ip}\""
    elif "rdp" in lowered or "4625" in lowered or "windows" in lowered:
        return f"Oct 16 12:00:00 win-server Microsoft-Windows-Security-Auditing[4625]: An account failed to log on. Account Name: Administrator, IpAddress: {target_ip}, FailureReason: Unknown user name or bad password."
    elif any(k in lowered for k in ["web", "http", "apache", "nginx", "403", "401", "sqli", "xss"]):
        if "sqli" in lowered or "union" in lowered or "select" in lowered:
            return f"{target_ip} - - [16/Oct/2026:12:00:00 +0000] \"GET /index.php?id=1%20UNION%20SELECT%201,2,version() HTTP/1.1\" 200 4500 \"-\" \"sqlmap/1.6\""
        elif "dir" in lowered or "scan" in lowered:
            return f"{target_ip} - - [16/Oct/2026:12:00:00 +0000] \"GET /.env HTTP/1.1\" 404 280 \"-\" \"Kali-Audit/1.0\""
        else:
            return f"{target_ip} - - [16/Oct/2026:12:00:00 +0000] \"POST /login.php HTTP/1.1\" 401 512 \"http://target/login.php\" \"Mozilla/5.0\""
    elif "sudo" in lowered or "su" in lowered:
        return f"Oct 16 12:00:00 server sudo: pam_unix(sudo:auth): authentication failure; logname=operator uid=1000 euid=0 tty=/dev/pts/1 ruser=operator rhost= user=root"
    elif "firewall" in lowered or "iptables" in lowered or "drop" in lowered:
        return f"Oct 16 12:00:00 server kernel: [IPTABLES DROP] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC={target_ip} DST=10.0.0.1 PROTO=TCP SPT=4444 DPT=80"
    else:
        # Default canonical auth failure
        return f"Oct 16 12:00:00 server sshd[1234]: Failed password for invalid user admin from {target_ip} port 22 ssh2"


def parse_logtest_output(raw_text: str) -> Dict[str, Any]:
    """
    Parse wazuh-logtest 3-phase execution stdout & stderr.
    """
    text = raw_text or ""
    phase1 = {}
    phase2 = {}
    phase3 = {}

    # Phase 1: pre-decoding
    p1_match = re.search(r"\*\*Phase 1: Completed pre-decoding\.(.*?)(?=\*\*Phase 2|\Z)", text, re.DOTALL)
    if p1_match:
        p1_text = p1_match.group(1)
        for line in p1_text.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                phase1[k.strip()] = v.strip().strip("'\"")

    # Phase 2: decoding
    p2_match = re.search(r"\*\*Phase 2: Completed decoding\.(.*?)(?=\*\*Phase 3|\Z)", text, re.DOTALL)
    if p2_match:
        p2_text = p2_match.group(1)
        for line in p2_text.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                phase2[k.strip()] = v.strip().strip("'\"")

    # Phase 3: filtering (rules)
    p3_match = re.search(r"\*\*Phase 3: Completed filtering \(rules\)\.(.*?)(?=\*\*Alert|\Z)", text, re.DOTALL)
    if p3_match:
        p3_text = p3_match.group(1)
        for line in p3_text.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                phase3[k.strip()] = v.strip().strip("'\"")

    alert_generated = "**Alert to be generated." in text

    rule_id = phase3.get("id")
    rule_id_int = int(rule_id) if rule_id and rule_id.isdigit() else None

    return {
        "phase1": phase1,
        "phase2": phase2,
        "phase3": phase3,
        "matched_rule_id": rule_id_int,
        "decoder_name": phase2.get("name") or phase1.get("program_name"),
        "alert_generated": alert_generated,
        "summary": (
            f"Decoder: '{phase2.get('name') or phase1.get('program_name') or 'unknown'}' | "
            f"Base Rule ID: {rule_id or 'None'} (Level {phase3.get('level', '?')}) | "
            f"Description: '{phase3.get('description', 'N/A')}'"
        )
    }


def test_log_event(log_line: str) -> Dict[str, Any]:
    """
    Execute wazuh-logtest on a given log line and return parsed ground-truth analysis.
    """
    clean_line = (log_line or "").strip()
    if not clean_line:
        return {"ok": False, "message": "Empty log line"}
    if len(clean_line) > 4096 or "\n" in clean_line or "\r" in clean_line:
        return {"ok": False, "message": "Log line must be a single line of at most 4096 characters"}

    check_res = run_logtest_check(clean_line)
    raw_combined = f"{check_res.get('stdout', '')}\n{check_res.get('stderr', '')}".strip()

    parsed = parse_logtest_output(raw_combined)
    return {
        "ok": check_res.get("ok", False),
        "tested_log": clean_line,
        "parsed": parsed,
        "matched_rule_id": parsed.get("matched_rule_id"),
        "decoder_name": parsed.get("decoder_name"),
        "summary": parsed.get("summary"),
        "raw_output": raw_combined,
    }
