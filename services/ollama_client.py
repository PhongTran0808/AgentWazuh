"""Small native Ollama HTTP client used by the AgentWazuh chat pipeline.

The PI CLI can expose Ollama models in its model list, but it is not a
reliable transport for the dashboard's long, evidence-grounded prompts. This
module talks to Ollama directly and supports the two local API shapes that
AgentWazuh has historically exposed: ``/api/generate`` and ``/api/chat``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

import requests


class OllamaError(RuntimeError):
    """Raised when Ollama cannot produce a usable response."""


def model_name_from_selection(selection: Optional[str]) -> Optional[str]:
    """Convert a dashboard model id such as ``ollama/qwen2.5:7b`` to a name."""
    value = str(selection or "").strip()
    if not value or value.lower() == "auto":
        return None
    if value.lower().startswith("ollama/"):
        return value.split("/", 1)[1].strip() or None
    return value


def tags_url(url: str) -> str:
    """Return Ollama's model-list endpoint for any configured local endpoint."""
    parsed = urlsplit((url or "http://127.0.0.1:11434/api/generate").strip())
    path = parsed.path.rstrip("/")
    if path.endswith("/api/generate") or path.endswith("/api/chat"):
        path = path.rsplit("/", 1)[0] + "/tags"
    elif path.endswith("/v1/chat/completions"):
        path = path[: -len("/v1/chat/completions")] + "/api/tags"
    elif not path or path == "/":
        path = "/api/tags"
    else:
        path = path + "/api/tags"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


@dataclass
class OllamaClient:
    url: str = "http://127.0.0.1:11434/api/generate"
    timeout_seconds: float = 120.0

    def _request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        endpoint = self.url.strip().rstrip("/")
        try:
            response = requests.post(
                endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=max(float(self.timeout_seconds), 1.0),
            )
        except requests.RequestException as exc:
            raise OllamaError(f"Không thể kết nối Ollama tại {endpoint}: {exc}") from exc

        if response.status_code != 200:
            detail = response.text.strip().replace("\n", " ")[:500]
            raise OllamaError(f"Ollama trả HTTP {response.status_code}: {detail or 'không có chi tiết'}")
        try:
            data = response.json()
        except ValueError as exc:
            raise OllamaError("Ollama trả về dữ liệu JSON không hợp lệ") from exc
        if not isinstance(data, dict):
            raise OllamaError("Ollama trả về payload không hợp lệ")
        return data

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str,
        *,
        temperature: float = 0.1,
        num_predict: int = 256,
    ) -> str:
        """Generate one non-streaming response from a local Ollama model."""
        endpoint = self.url.lower().rstrip("/")
        # Local SOC chat should stay responsive on CPU/VRAM-constrained hosts.
        # The deterministic Python layer already carries the full evidence;
        # Ollama only needs to synthesize a concise analyst-facing response.
        system_prompt = (
            f"{system_prompt}\n\n"
            "YÊU CẦU CHO MODEL LOCAL: Trả lời cô đọng, tối đa khoảng 180 từ "
            "hoặc 8 gạch đầu dòng; chỉ dùng số liệu trong bối cảnh."
        )
        options = {
            "temperature": temperature,
            "num_predict": max(int(num_predict), 128),
        }

        if endpoint.endswith("/v1/chat/completions"):
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": temperature,
                "max_tokens": max(int(num_predict), 128),
                "stream": False,
            }
            data = self._request(payload)
            choices = data.get("choices") or []
            text = ((choices[0].get("message") or {}).get("content") if choices else "") or ""
        elif endpoint.endswith("/api/chat"):
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "options": options,
                "keep_alive": "10m",
            }
            data = self._request(payload)
            text = ((data.get("message") or {}).get("content") or "")
        else:
            # /api/generate is retained for compatibility with the existing
            # AgentWazuh setting and accepts the system prompt separately.
            payload = {
                "model": model,
                "system": system_prompt,
                "prompt": user_prompt,
                "stream": False,
                "raw": False,
                "options": options,
                "keep_alive": "10m",
            }
            data = self._request(payload)
            text = data.get("response") or ""

        text = str(text).strip()
        if not text:
            raise OllamaError("Ollama trả về phản hồi rỗng")
        return text

    def list_models(self) -> list[Dict[str, Any]]:
        """Return model metadata without exposing local prompt contents."""
        endpoint = tags_url(self.url)
        try:
            response = requests.get(endpoint, timeout=min(max(float(self.timeout_seconds), 1.0), 10.0))
        except requests.RequestException as exc:
            raise OllamaError(f"Không thể đọc danh sách model Ollama: {exc}") from exc
        if response.status_code != 200:
            raise OllamaError(f"Ollama trả HTTP {response.status_code} khi đọc danh sách model")
        try:
            data = response.json()
        except ValueError as exc:
            raise OllamaError("Ollama trả danh sách model không hợp lệ") from exc
        models = data.get("models") if isinstance(data, dict) else None
        if not isinstance(models, list):
            raise OllamaError("Ollama không trả trường models")
        return [item for item in models if isinstance(item, dict) and item.get("name")]
