"""Guarded local Wazuh configuration manager.

This module never writes a Wazuh file without first creating a timestamped
backup. It is intentionally separate from the upstream MCP server because the
upstream project exposes active-response writes, not rule/decoder/ossec.conf
file management.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from xml.etree import ElementTree


class WazuhConfigError(RuntimeError):
    pass


WAZUH_ETC = Path(os.getenv("WAZUH_ETC_DIR", "/var/ossec/etc"))
BACKUP_ROOT = Path(os.getenv("WAZUH_CONFIG_BACKUP_DIR", "data/wazuh_config_backups"))
AUDIT_PATH = Path(os.getenv("WAZUH_CONFIG_AUDIT_LOG", "logs/wazuh_config_audit.jsonl"))

_ALLOWED_FILES = {
    "rules": WAZUH_ETC / "rules" / "local_rules.xml",
    "decoders": WAZUH_ETC / "decoders" / "local_decoder.xml",
    "ossec": WAZUH_ETC / "ossec.conf",
}
PRIVILEGED_HELPER = Path(os.getenv("WAZUH_CONFIG_HELPER", "/usr/local/sbin/agentwazuh-wazuh-config"))


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _audit(event: str, payload: Dict[str, Any]) -> None:
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **payload}
    with AUDIT_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def _read_target(kind: str) -> tuple[Path, str]:
    if kind not in _ALLOWED_FILES:
        raise WazuhConfigError(f"Unsupported Wazuh config target: {kind}")
    path = _ALLOWED_FILES[kind]
    if PRIVILEGED_HELPER.exists():
        result = _helper({"action": "read", "target": kind})
        return path, str(result.get("content", ""))
    try:
        if not path.exists():
            raise WazuhConfigError(f"Wazuh config file does not exist: {path}")
    except PermissionError as exc:
        raise WazuhConfigError(f"Permission denied reading {path}; install the privileged config helper") from exc
    try:
        return path, path.read_text(encoding="utf-8")
    except PermissionError as exc:
        raise WazuhConfigError(f"Permission denied reading {path}; install the privileged config helper") from exc


def _helper(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            ["sudo", "-n", str(PRIVILEGED_HELPER)],
            input=json.dumps(payload), text=True, capture_output=True, timeout=45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WazuhConfigError(f"Wazuh config helper unavailable: {exc}") from exc
    try:
        result = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise WazuhConfigError("Wazuh config helper returned invalid JSON") from exc
    if proc.returncode != 0 or not result.get("ok"):
        detail = (
            result.get("message")
            or result.get("stderr")
            or result.get("stdout")
            or proc.stderr.strip()
            or proc.stdout.strip()
            or "Wazuh config helper failed"
        )
        raise WazuhConfigError(detail)
    return result


def _validate(kind: str, content: str) -> None:
    if not content.strip():
        raise WazuhConfigError("Refusing to write an empty Wazuh configuration")
    if kind in {"rules", "decoders", "ossec"}:
        try:
            ElementTree.fromstring(content)
        except ElementTree.ParseError as exc:
            raise WazuhConfigError(f"Invalid XML for {kind}: {exc}") from exc
    if kind == "ossec" and "<ossec_config" not in content:
        raise WazuhConfigError("ossec.conf must contain the ossec_config root element")
    if kind == "rules" and "<group" not in content:
        raise WazuhConfigError("local_rules.xml must contain at least one group element")
    if kind == "decoders" and "<decoder" not in content:
        raise WazuhConfigError("local_decoder.xml must contain at least one decoder element")


def _backup(path: Path) -> Path:
    target_dir = BACKUP_ROOT / _stamp()
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / path.name
    shutil.copy2(path, target)
    return target


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def preview(kind: str, content: str) -> Dict[str, Any]:
    path, current = _read_target(kind)
    _validate(kind, content)
    return {
        "approval_id": uuid.uuid4().hex,
        "target": kind,
        "path": str(path),
        "changed": current != content,
        "before_sha256": hashlib.sha256(current.encode()).hexdigest(),
        "after_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "before_bytes": len(current.encode()),
        "after_bytes": len(content.encode()),
    }


def apply(kind: str, content: str, approval_id: str, approved: bool = False, actor: str = "unknown") -> Dict[str, Any]:
    if not approved:
        raise WazuhConfigError("Explicit approval is required before applying Wazuh configuration")
    if not approval_id:
        raise WazuhConfigError("approval_id is required")
    path, current = _read_target(kind)
    _validate(kind, content)
    helper_result = _helper({
        "action": "write", "target": kind, "content": content,
        "approval_id": approval_id, "approved": True,
    })
    result = {
        "target": kind,
        "path": str(path),
        "backup": helper_result.get("backup"),
        "approval_id": approval_id,
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
    }
    _audit("config_apply", {"actor": actor, "result": result, "before_sha256": hashlib.sha256(current.encode()).hexdigest()})
    return result


def merge_rule_group(current: str, candidate: str) -> tuple[str, list[str]]:
    """Merge a rule-group draft into local_rules.xml without duplicating IDs."""
    try:
        current_root = ElementTree.fromstring(current)
        candidate_root = ElementTree.fromstring(candidate)
    except ElementTree.ParseError as exc:
        raise WazuhConfigError(f"Invalid rule XML: {exc}") from exc

    if candidate_root.tag != "group":
        raise WazuhConfigError("Rule draft must have a <group> root element")
    candidate_rules = candidate_root.findall(".//rule")
    if not candidate_rules:
        raise WazuhConfigError("Rule draft does not contain a <rule> element")
    candidate_ids = []
    for rule in candidate_rules:
        rule_id = (rule.get("id") or "").strip()
        if not rule_id:
            raise WazuhConfigError("Every rule must have an id")
        # Wazuh requires an if_matched_* clause for frequency/timeframe.
        # Normalize older drafts that incorrectly used if_sid so analysisd
        # does not reject the complete local_rules.xml file.
        # Accept old drafts that emitted frequency/timeframe as child tags,
        # but write the Wazuh-supported rule attributes.
        for option in ("frequency", "timeframe"):
            child = rule.find(option)
            if not (rule.get(option) or "").strip() and child is not None and (child.text or "").strip():
                rule.set(option, child.text.strip())
            if child is not None:
                rule.remove(child)
        has_correlation_window = any(
            (rule.get(name) or "").strip() for name in ("frequency", "timeframe")
        )
        if has_correlation_window and rule.find("if_matched_sid") is None and rule.find("if_matched_group") is None:
            legacy_parent = rule.find("if_sid")
            if legacy_parent is not None:
                legacy_parent.tag = "if_matched_sid"
            else:
                raise WazuhConfigError(
                    f"Rule {rule_id} dùng frequency/timeframe nhưng thiếu if_matched_sid hoặc if_matched_group"
                )
        candidate_ids.append(rule_id)
    if len(candidate_ids) != len(set(candidate_ids)):
        raise WazuhConfigError("Rule draft contains duplicate rule IDs")

    existing_ids = {
        (rule.get("id") or "").strip()
        for rule in current_root.findall(".//rule")
        if rule.get("id")
    }
    duplicates = sorted(set(candidate_ids) & existing_ids)
    if duplicates:
        raise WazuhConfigError(f"Rule ID already exists in local_rules.xml: {', '.join(duplicates)}")

    # The installed Wazuh file uses a single <group> root. Inject the draft's
    # rule elements as text so existing comments and formatting stay intact.
    if current_root.tag == "group" and current.rstrip().endswith("</group>"):
        pieces = [ElementTree.tostring(rule, encoding="unicode") for rule in candidate_rules]
        insertion = "\n\n" + "\n\n".join(pieces) + "\n"
        merged = current.rstrip()[:-len("</group>")] + insertion + "</group>\n"
    else:
        for rule in candidate_rules:
            current_root.append(rule)
        merged = ElementTree.tostring(current_root, encoding="unicode") + "\n"
    _validate("rules", merged)
    return merged, candidate_ids


def restore(kind: str, backup: str, approval_id: str, approved: bool = False, actor: str = "unknown") -> Dict[str, Any]:
    if not approved or not approval_id:
        raise WazuhConfigError("Explicit approval is required before restoring Wazuh configuration")
    path, _ = _read_target(kind)
    result = _helper({
        "action": "restore", "target": kind, "backup": backup,
        "approval_id": approval_id, "approved": True,
    })
    _audit("config_restore", {"actor": actor, "target": kind, "path": str(path), "backup": backup, "approval_id": approval_id})
    return result


def restart_manager() -> Dict[str, Any]:
    if not PRIVILEGED_HELPER.exists():
        return {"ok": False, "message": "Privileged Wazuh config helper is not installed"}
    try:
        return _helper({"action": "restart"})
    except WazuhConfigError as exc:
        return {"ok": False, "message": str(exc)}


def validate_runtime() -> Dict[str, Any]:
    """Run the installed Wazuh syntax check when the caller has permission."""
    if PRIVILEGED_HELPER.exists():
        try:
            return _helper({"action": "validate"})
        except WazuhConfigError as exc:
            return {"ok": False, "message": str(exc)}
    commands = [["/var/ossec/bin/wazuh-analysisd", "-t"]]
    for command in commands:
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        except (FileNotFoundError, PermissionError) as exc:
            return {"ok": False, "message": str(exc), "command": command}
        return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-4000:]}
    return {"ok": False, "message": "No validator configured"}
