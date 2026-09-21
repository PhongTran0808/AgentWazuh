"""Small Streamable-HTTP MCP client for the local Wazuh MCP server.

The upstream Wazuh-MCP-Server implements the MCP protocol directly over HTTP.
Keeping this client in AgentWazuh gives the application one place to enforce
timeouts, authentication, tool discovery, and audit-safe error handling.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx


class WazuhMCPError(RuntimeError):
    """A connection or protocol error talking to the Wazuh MCP server."""


def _load_local_env() -> None:
    """Load the local MCP env file without logging any secret values."""
    env_file = Path(
        os.getenv(
            "AGENTWAZUH_MCP_ENV_FILE",
            Path(__file__).resolve().parent.parent / "reference/Wazuh-MCP-Server/config/wazuh.env",
        )
    )
    if not env_file.exists():
        return
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


class WazuhMCPClient:
    """Authenticated MCP client for the local upstream Wazuh server."""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None, timeout: float = 15.0):
        _load_local_env()
        self.base_url = (base_url or os.getenv("AGENTWAZUH_MCP_URL", "http://127.0.0.1:3000")).rstrip("/")
        self.api_key = api_key or os.getenv("MCP_API_KEY", "")
        self.timeout = timeout

    async def _request_json(self, client: httpx.AsyncClient, method: str, path: str, **kwargs: Any) -> Dict[str, Any]:
        try:
            response = await client.request(method, f"{self.base_url}{path}", **kwargs)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise WazuhMCPError(f"MCP returned a non-object response for {path}")
            return data
        except (httpx.HTTPError, ValueError) as exc:
            raise WazuhMCPError(f"MCP request failed ({path}): {exc}") from exc

    async def health(self) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            return await self._request_json(client, "GET", "/health")

    async def _access_token(self, client: httpx.AsyncClient) -> str:
        if not self.api_key:
            raise WazuhMCPError("MCP_API_KEY is not configured")
        result = await self._request_json(client, "POST", "/auth/token", json={"api_key": self.api_key})
        token = result.get("access_token")
        if not token:
            raise WazuhMCPError("MCP token response did not contain access_token")
        return str(token)

    async def _session(self, client: httpx.AsyncClient) -> tuple[str, str]:
        token = await self._access_token(client)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "agentwazuh", "version": "1.0"},
            },
        }
        response = await client.post(f"{self.base_url}/mcp", headers=headers, json=payload)
        if response.status_code >= 400:
            raise WazuhMCPError(f"MCP initialize failed: HTTP {response.status_code}")
        session_id = response.headers.get("mcp-session-id")
        if not session_id:
            raise WazuhMCPError("MCP initialize did not return a session id")
        return session_id, token

    @staticmethod
    def _extract_result(response: httpx.Response) -> Dict[str, Any]:
        try:
            data = response.json()
        except ValueError:
            # Some MCP deployments return one JSON-RPC envelope as an SSE data line.
            data = None
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    try:
                        data = json.loads(line[5:].strip())
                        break
                    except ValueError:
                        continue
            if data is None:
                raise WazuhMCPError("MCP returned an unreadable response")
        if "error" in data:
            raise WazuhMCPError(str(data["error"]))
        return data.get("result", data)

    async def _call(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            session_id, token = await self._session(client)
            headers = {
                "Authorization": f"Bearer {token}",
                "Mcp-Session-Id": session_id,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }
            payload = {"jsonrpc": "2.0", "id": 2, "method": method, "params": params}
            try:
                response = await client.post(f"{self.base_url}/mcp", headers=headers, json=payload)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                raise WazuhMCPError(f"MCP call failed ({method}): {exc}") from exc
            return self._extract_result(response)

    async def list_tools(self) -> list[Dict[str, Any]]:
        result = await self._call("tools/list", {})
        tools = result.get("tools", [])
        return tools if isinstance(tools, list) else []

    async def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not name or not isinstance(name, str):
            raise WazuhMCPError("MCP tool name must be a non-empty string")
        return await self._call("tools/call", {"name": name, "arguments": arguments or {}})


def run_mcp(coro: Any) -> Any:
    """Run an MCP coroutine from synchronous application/tool code."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise WazuhMCPError("Use the async MCP methods from an active event loop")
