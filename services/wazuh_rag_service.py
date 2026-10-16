"""
Wazuh RAG Knowledge Base Bridge for Rule Generation & Investigation.
Integrates Chroma DB & BAAI/bge-m3 embedding from `docs/wazuh_kb_local.py`.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from integrations.wazuh_config_manager import WazuhConfigError

logger = logging.getLogger("WazuhRAGService")

BASE_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = BASE_DIR / "docs"

# Add docs to sys.path so wazuh_kb_local can be imported cleanly
if str(DOCS_DIR) not in sys.path:
    sys.path.insert(0, str(DOCS_DIR))

if not os.environ.get("WAZUH_KB_PATH"):
    os.environ["WAZUH_KB_PATH"] = str(DOCS_DIR / "wazuh_kb_local")

os.environ.setdefault("HF_HUB_OFFLINE", "1")

try:
    import wazuh_kb_local as kb
    HAS_KB_MODULE = True
except Exception as exc:
    logger.warning("Could not import wazuh_kb_local: %s", exc)
    HAS_KB_MODULE = False
    kb = None


def search_docs(query: str, k: int = 5) -> str:
    """
    Search official Wazuh 4.14 documentation chunks via Chroma + BM25 hybrid search.
    Falls back gracefully to curated Wazuh 4.14 rule-syntax handbook if Chroma is unavailable.
    """
    if HAS_KB_MODULE and kb is not None:
        try:
            res = kb.search_wazuh_docs(query, k=k)
            if res and "Knowledge base is empty" not in res and "No results" not in res:
                return res
        except Exception as exc:
            logger.warning("wazuh_kb_local.search_wazuh_docs failed: %s", exc)

    return _fallback_wazuh_docs_context(query)


def search_local(query: str, k: int = 5) -> str:
    """
    Search local custom rules in /var/ossec/etc/rules or config/local_rules.xml.
    """
    if HAS_KB_MODULE and kb is not None:
        try:
            res = kb.search_local_rules(query, k=k)
            if res and "No local rules indexed" not in res:
                return res
        except Exception as exc:
            logger.warning("wazuh_kb_local.search_local_rules failed: %s", exc)

    # Fallback: scan local XML files directly
    return _fallback_local_rules_search(query)


def get_next_free_rule_id(etc_dir: str = "/var/ossec/etc") -> int:
    """
    Find the next available custom rule ID in range 100000-120000.
    """
    return _fallback_next_rule_id(etc_dir)


def _fallback_next_rule_id(etc_dir: str) -> int:
    used = set()
    readable_source = False
    try:
        for rules_file in Path(etc_dir).glob("rules/*.xml"):
            try:
                text = rules_file.read_text(encoding="utf-8", errors="ignore")
                used.update(int(x) for x in re.findall(r'<rule\s[^>]*?\bid=["\'](\d+)["\']', text))
                readable_source = True
            except OSError as exc:
                logger.debug("Could not read rule file %s: %s", rules_file, exc)
    except OSError as exc:
        logger.debug("Could not list Wazuh rule files under %s: %s", etc_dir, exc)

    try:
        from integrations.wazuh_config_manager import _read_target
        _, text = _read_target("rules")
        used.update(int(x) for x in re.findall(r'<rule\s[^>]*?\bid=["\'](\d+)["\']', text))
        readable_source = True
    except Exception as exc:
        logger.debug("Could not read active Wazuh rules: %s", exc)

    fallback_file = BASE_DIR / "config" / "local_rules.xml"
    if fallback_file.is_file():
        try:
            text = fallback_file.read_text(encoding="utf-8", errors="ignore")
            used.update(int(x) for x in re.findall(r'<rule\s[^>]*?\bid=["\'](\d+)["\']', text))
            readable_source = True
        except OSError as exc:
            logger.warning("Could not read fallback rule file %s: %s", fallback_file, exc)

    if not readable_source:
        raise WazuhConfigError("Unable to inspect any Wazuh rules file to allocate a safe rule ID")
    for candidate in range(100001, 120001):
        if candidate not in used:
            return candidate
    raise WazuhConfigError("No free custom Wazuh rule IDs remain in range 100001-120000")


def _fallback_local_rules_search(query: str) -> str:
    matches = []
    q_words = [w.lower() for w in re.findall(r"\w+", query) if len(w) > 2]
    texts = []
    try:
        from integrations.wazuh_config_manager import _read_target
        _, t = _read_target("rules")
        if t:
            texts.append(t)
    except Exception:
        pass

    fallback_file = BASE_DIR / "config" / "local_rules.xml"
    if fallback_file.is_file():
        try:
            texts.append(fallback_file.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            pass

    for text in texts:
        for rule_block in re.findall(r"(<rule\s+[^>]*>[\s\S]*?</rule>)", text):
            b_lower = rule_block.lower()
            if any(w in b_lower for w in q_words):
                matches.append(rule_block.strip())

    return "\n\n---\n\n".join(matches[:5]) or "No relevant local rules found."


def _fallback_wazuh_docs_context(query: str) -> str:
    """
    Curated Wazuh 4.14 rule-syntax documentation handbook for reliable fallback.
    """
    return """### [Wazuh 4.14 Official Rule Syntax Guidelines]
1. Frequency & Timeframe Rules (Correlation Windows):
   - In Wazuh 4.14, 'frequency' and 'timeframe' MUST be attributes on the <rule> element:
     <rule id="100501" level="10" frequency="5" timeframe="60">
   - Frequency rules MUST use <if_matched_sid> or <if_matched_group> to specify the parent alert.
   - Do NOT use <if_sid> with frequency/timeframe (wazuh-analysisd will reject it).
   - <same_source_ip /> or <same_field>fieldname</same_field> should be used to correlate by entity.

2. Matching Options:
   - <match>: Simple case-insensitive string match.
   - <regex>: OS_Regex syntax.
   - <pcre2>: Full Perl-compatible regular expressions (Wazuh 4.4+).
   - <field name="field_name">: Matches specific dynamic decoder field.

3. MITRE ATT&CK Mapping:
   - Include <mitre><id>TXXXX</id></mitre> inside the <rule> tag.

4. Rule Groups:
   - All rules must belong to a <group name="..."> root or group tag.
   - Standard groups: sshd, web_attack, authentication_failures, syslog, custom_rules.
"""
