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

# Load secrets into this launcher process. Running `bash setup3.sh` in a
# separate shell cannot export variables into the later `bash start...` call.
# The path is configurable, with the user's existing PNETLAB bootstrap as the
# default. pass.env is loaded last so local project values can override it.
ENV_BOOTSTRAP_FILE="${AGENTWAZUH_ENV_BOOTSTRAP:-/home/xinloihuy/PNETLAB/setup3.sh}"
if [[ -f "$ENV_BOOTSTRAP_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_BOOTSTRAP_FILE"
  set +a
fi
if [[ -f "$BASE_DIR/pass.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$BASE_DIR/pass.env"
  set +a
  chmod 600 "$BASE_DIR/pass.env" 2>/dev/null || true
fi

PY_BIN=""
for PY_CANDIDATE in python3.12 python3.11 python3.10 python3; do
  if command -v "$PY_CANDIDATE" >/dev/null 2>&1 && \
     "$PY_CANDIDATE" -c 'import fastapi, uvicorn, telegram, cryptography, networkx' >/dev/null 2>&1; then
    PY_BIN="$(command -v "$PY_CANDIDATE")"
    break
  fi
done

if [[ -z "$PY_BIN" ]]; then
  for PY_CANDIDATE in python3.12 python3.11 python3.10 python3; do
    if command -v "$PY_CANDIDATE" >/dev/null 2>&1; then
      PY_BIN="$(command -v "$PY_CANDIDATE")"
      break
    fi
  done
fi

if [[ -z "$PY_BIN" ]]; then
  echo "Không tìm thấy Python 3.10+ trên hệ thống." >&2
  exit 1
fi

USER_HOME="$(getent passwd "$(id -u)" | cut -d: -f6)"
export PATH="$USER_HOME/.local/bin:$PATH"
export PYTHONUNBUFFERED=1
mkdir -p "$BASE_DIR/logs"

if ! "$PY_BIN" -c 'import fastapi, uvicorn, telegram, cryptography, networkx' >/dev/null 2>&1; then
  echo "Thiếu dependency Python (bao gồm python-telegram-bot). Đang cài đặt..." >&2
  if ! "$PY_BIN" -m pip install --user --break-system-packages -r "$BASE_DIR/requirements.txt"; then
    echo "Cài dependency thất bại. Chạy thủ công: $PY_BIN -m pip install -r $BASE_DIR/requirements.txt" >&2
    exit 1
  fi
fi

if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]]; then
  echo "✅ Telegram bridge sẽ được khởi động cùng AgentWazuh"
else
  echo "⚠️ Chưa cấu hình TELEGRAM_BOT_TOKEN; web dashboard vẫn khởi động, Telegram bridge sẽ tắt"
fi

if [[ -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
  echo "✅ Discord alert forwarding sẽ được khởi động cùng AgentWazuh"
else
  echo "⚠️ Chưa cấu hình DISCORD_WEBHOOK_URL; Discord forwarding sẽ tắt"
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

# Kill existing process running on port 8080 if any
EXISTING_PID="$(lsof -t -i:8080 2>/dev/null || true)"
if [[ -n "$EXISTING_PID" ]]; then
  echo "🔄 Đang tắt tiến trình cũ (PID: $EXISTING_PID) đang chiếm port 8080..."
  kill -9 $EXISTING_PID 2>/dev/null || true
  sleep 1
fi

exec "$PY_BIN" -m uvicorn core.server:app --host 0.0.0.0 --port 8080
