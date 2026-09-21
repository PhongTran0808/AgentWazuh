#!/usr/bin/env bash
# ==============================================================================
# AgentWazuh 1-Line Setup & Startup Launcher
# Auto-detects Python 3.11+ on Amazon Linux 2023 / RHEL / Ubuntu
# ==============================================================================

set -Eeuo pipefail

# Stable local launcher for AgentWazuh + the local Wazuh MCP server.
# Reuses an already healthy MCP instance and avoids Uvicorn's dev reloader.
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

if command -v python3.11 >/dev/null 2>&1; then
  PY_BIN="$(command -v python3.11)"
elif command -v python3.10 >/dev/null 2>&1; then
  PY_BIN="$(command -v python3.10)"
else
  PY_BIN="$(command -v python3)"
fi

USER_HOME="$(getent passwd "$(id -u)" | cut -d: -f6)"
export PATH="$USER_HOME/.local/bin:$PATH"
export PYTHONUNBUFFERED=1
mkdir -p "$BASE_DIR/logs"

if ! "$PY_BIN" -c 'import fastapi, uvicorn' >/dev/null 2>&1; then
  echo "Thiếu dependency Python. Chạy: $PY_BIN -m pip install -r $BASE_DIR/requirements.txt" >&2
  exit 1
fi

MCP_URL="http://127.0.0.1:3000"
if curl -fsS --max-time 2 "$MCP_URL/health" >/dev/null 2>&1; then
  echo "✅ MCP đang chạy: $MCP_URL"
elif command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet agentwazuh-mcp.service 2>/dev/null; then
  echo "🚀 Khởi động AgentWazuh MCP bằng systemd..."
  if sudo -n systemctl start agentwazuh-mcp.service 2>/dev/null; then
    for _ in {1..20}; do
      curl -fsS --max-time 2 "$MCP_URL/health" >/dev/null 2>&1 && break
      sleep 0.5
    done
    if ! curl -fsS --max-time 2 "$MCP_URL/health" >/dev/null 2>&1 && systemctl is-active --quiet agentwazuh-mcp.service; then
      for _ in {1..20}; do
        curl -fsS --max-time 2 "$MCP_URL/health" >/dev/null 2>&1 && break
        sleep 0.5
      done
    fi
  else
    echo "⚠️ Không có sudo không-mật-khẩu; chạy MCP ở user mode..."
  fi
fi

if ! curl -fsS --max-time 2 "$MCP_URL/health" >/dev/null 2>&1; then
  echo "🚀 Khởi động AgentWazuh MCP user process..."
  nohup "$BASE_DIR/start_wazuh_mcp.sh" >"$BASE_DIR/logs/wazuh-mcp.log" 2>&1 &
  MCP_PID=$!
  for _ in {1..30}; do
    curl -fsS --max-time 2 "$MCP_URL/health" >/dev/null 2>&1 && break
    if ! kill -0 "$MCP_PID" 2>/dev/null; then
      echo "MCP khởi động thất bại; xem $BASE_DIR/logs/wazuh-mcp.log" >&2
      exit 1
    fi
    sleep 0.5
  done
fi

if ! curl -fsS --max-time 2 "$MCP_URL/health" >/dev/null 2>&1; then
  echo "MCP chưa sẵn sàng tại $MCP_URL" >&2
  exit 1
fi

echo "✅ MCP sẵn sàng tại $MCP_URL"
echo "⚡ AgentWazuh web chạy tại http://127.0.0.1:8080"
exec "$PY_BIN" -m uvicorn core.server:app --host 0.0.0.0 --port 8080
