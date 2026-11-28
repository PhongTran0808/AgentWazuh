"""IP Pseudonymization / Anonymization middleware for Cloud LLM API privacy.

Replaces real IPv4 addresses with deterministic per-request placeholders
(e.g., ``IP_INTERNAL_1``, ``IP_EXTERNAL_1``) before sending prompts or
structured incident payloads to external Cloud APIs (Gemini, OpenRouter,
OpenAI), then restores the original IP addresses in the model's response
before returning it to the SOC Analyst.

Local LLM calls (Ollama / Qwen running inside the private network) bypass
this layer since data never leaves the local environment.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict

# Match standalone IPv4 literals (even before a sentence-ending period)
# without colliding with 5-part version numbers (e.g. 4.14.0.1.2).
_IPV4_PATTERN = re.compile(
    r"(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)(?!\.\d)"
)

_SKIP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


class IPAnonymizer:
    """Bidirectional IPv4 pseudonymizer scoped to a single Cloud API request."""

    def __init__(self) -> None:
        self.real_to_alias: Dict[str, str] = {}
        self.alias_to_real: Dict[str, str] = {}
        self._internal_counter = 0
        self._external_counter = 0

    def _alias_for(self, ip_str: str) -> str:
        if ip_str in _SKIP_IPS:
            return ip_str
        if ip_str in self.real_to_alias:
            return self.real_to_alias[ip_str]
        try:
            addr = ipaddress.IPv4Address(ip_str)
        except ValueError:
            return ip_str

        if addr.is_private or addr.is_link_local:
            self._internal_counter += 1
            alias = f"IP_INTERNAL_{self._internal_counter}"
        else:
            self._external_counter += 1
            alias = f"IP_EXTERNAL_{self._external_counter}"

        self.real_to_alias[ip_str] = alias
        self.alias_to_real[alias] = ip_str
        return alias

    def anonymize_text(self, text: str) -> str:
        """Replace real IPv4 addresses in ``text`` with temporary aliases."""
        if not text:
            return text
        return _IPV4_PATTERN.sub(lambda m: self._alias_for(m.group(0)), text)

    def deanonymize_text(self, text: str) -> str:
        """Restore temporary IP aliases in ``text`` back to original IPv4s."""
        if not text or not self.alias_to_real:
            return text
        # Replace longer aliases first so IP_INTERNAL_10 is not broken by IP_INTERNAL_1
        restored = text
        for alias in sorted(self.alias_to_real, key=len, reverse=True):
            restored = restored.replace(alias, self.alias_to_real[alias])
        return restored

    def anonymize_data(self, obj: Any) -> Any:
        """Recursively pseudonymize IPv4 strings inside dicts/lists."""
        if isinstance(obj, str):
            return self.anonymize_text(obj)
        if isinstance(obj, list):
            return [self.anonymize_data(item) for item in obj]
        if isinstance(obj, dict):
            return {k: self.anonymize_data(v) for k, v in obj.items()}
        return obj

    def deanonymize_data(self, obj: Any) -> Any:
        """Recursively restore IPv4 aliases inside dicts/lists."""
        if isinstance(obj, str):
            return self.deanonymize_text(obj)
        if isinstance(obj, list):
            return [self.deanonymize_data(item) for item in obj]
        if isinstance(obj, dict):
            return {k: self.deanonymize_data(v) for k, v in obj.items()}
        return obj
