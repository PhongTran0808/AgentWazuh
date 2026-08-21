# ARCHITECTURE DECISIONS - AGENTWAZUH (PI-LANG-MCP)

## ADR-001: Modular Architecture Standardization
- **Decided**: Migrate flat file structure into 5 distinct specialized packages: `core/`, `services/`, `mcp_layer/`, `langgraph_engine/`, `tools/`.
- **Rationale**: Prevents technical debt, circular imports, and allows clean isolation between web API, SIEM connectors, MCP tools, and graph engines.

## ADR-002: Dual-Mode Connection & Fallback to Wazuh SIEM
- **Decided**: `WazuhClient` connects directly to REST API (Port 55000) using JWT authentication with readonly account `agentwazuh`. If REST API is restarting or restricted, it falls back to Wazuh Dashboard (Port 443) OpenSearch Console Proxy (`/api/console/proxy`).
- **Rationale**: Guarantees 99.9% data availability even during Wazuh Manager API maintenance windows.

## ADR-003: Model Synchronization to (github-copilot) gpt-4.1
- **Decided**: Default PI Agent CLI model is explicitly bound to `github-copilot/gpt-4.1`.
- **Rationale**: Ensures zero hallucination, fast response times, and full synchronization with active local development environment.

## ADR-004: Incident Case Management & Generative UI Integration
- **Decided**: Created `services/case_manager.py` and `tools/` directory containing `case_management_tool.py` (TheHive v5 / Jira / Webhook dispatch) and `generative_ui_tool.py` (FastUI & Pydantic DataGrid Engine).
- **Rationale**: Transforms AgentWazuh from terminal output into an Enterprise SOAR platform capable of generating structured HTML DataGrids and dispatching actionable tickets to SOC analysts.
