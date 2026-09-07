"""
Wazuh MCP Server & Tool Registry Layer:
Exposes Wazuh Model Context Protocol (MCP) tools for AI Agent orchestration.
"""

from typing import Dict, Any, List, Union, Callable
from mcp_layer.correlation_mcp import search_correlated_events, OpenSearchCorrelationTool

TOOL_DEFINITIONS = [
    {
        "name": "search_correlated_events",
        "description": "Retro-hunt correlated alerts across all network devices for a target IP within +/- 15 minutes window.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_ip": {
                    "type": "string",
                    "description": "Target IP address (attacker srcip, target dstip) to retro-hunt across network devices."
                },
                "base_timestamp": {
                    "type": "string",
                    "description": "Base timestamp (ISO 8601 string) around which to search (+/- time_window_minutes)."
                },
                "time_window_minutes": {
                    "type": "integer",
                    "default": 15,
                    "description": "Time window in minutes to search before and after base_timestamp (default: 15)."
                }
            },
            "required": ["target_ip", "base_timestamp"]
        }
    }
]

class WazuhMCPServer:
    """Wazuh MCP Tool Handler and Dispatcher."""

    def __init__(self):
        self.tools: Dict[str, Callable] = {
            "search_correlated_events": search_correlated_events
        }

    def list_tools(self) -> List[Dict[str, Any]]:
        """Returns registered MCP tool schemas."""
        return TOOL_DEFINITIONS

    def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Executes an MCP tool by name with arguments."""
        if name not in self.tools:
            return f"[MCP Error]: Tool '{name}' not found."

        try:
            return self.tools[name](**arguments)
        except Exception as e:
            return f"[MCP Tool Execution Error]: {str(e)}"

# Singleton Instance
wazuh_mcp_server = WazuhMCPServer()
