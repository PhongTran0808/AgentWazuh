#!/usr/bin/env bash
# ==============================================================================
# AgentWazuh 1-Line Setup & Startup Launcher
# Auto-detects Python 3.11+ on Amazon Linux 2023 / RHEL / Ubuntu
# ==============================================================================

if command -v python3.11 >/dev/null 2>&1; then
    PY_BIN="python3.11"
elif command -v python3.10 >/dev/null 2>&1; then
    PY_BIN="python3.10"
else
    PY_BIN="python3"
fi

echo "🚀 [AgentWazuh] Using $PY_BIN ($($PY_BIN --version 2>&1)). Installing requirements..."
$PY_BIN -m pip install -r requirements.txt --break-system-packages --quiet 2>/dev/null || $PY_BIN -m pip install -r requirements.txt --quiet

echo "⚡ [AgentWazuh] Starting AgentWazuh AI SOC Assistant on http://0.0.0.0:8000..."
exec $PY_BIN server.py
