#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_DIR="$BASE_DIR/reference/Wazuh-MCP-Server"
ENV_FILE="$MCP_DIR/config/wazuh.env"
MCP_URL="http://127.0.0.1:3000"

# MCP is normally managed by systemd. Reuse a healthy instance when this
# script is invoked manually so it never creates a second listener on :3000.
if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 "$MCP_URL/health" >/dev/null 2>&1; then
  echo "✅ AgentWazuh MCP đã chạy tại $MCP_URL (reuse instance hiện có)."
  exit 0
fi

if [[ ! -x "$MCP_DIR/.venv/bin/python" ]]; then
  echo "Wazuh MCP virtualenv chưa được cài: $MCP_DIR/.venv" >&2
  exit 1
fi
if [[ ! -r "$ENV_FILE" ]]; then
  echo "Thiếu file cấu hình MCP: $ENV_FILE" >&2
  exit 1
fi

cd "$MCP_DIR"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
export PYTHONUNBUFFERED=1
exec "$MCP_DIR/.venv/bin/python" -m wazuh_mcp_server
