#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_DIR="$BASE_DIR/reference/Wazuh-MCP-Server"
ENV_FILE="$MCP_DIR/config/wazuh.env"

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
exec "$MCP_DIR/.venv/bin/python" -m wazuh_mcp_server
