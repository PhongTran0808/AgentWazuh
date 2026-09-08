#!/usr/bin/env bash
# ==============================================================================
# AgentWazuh 1-Line Setup & Startup Launcher
# Runs seamlessly on both Local PC and Wazuh Server Linux (Localhost 127.0.0.1)
# ==============================================================================

echo "🚀 [AgentWazuh] Checking Python dependencies..."
python3 -m pip install -r requirements.txt --quiet 2>/dev/null || pip install -r requirements.txt --quiet

echo "⚡ [AgentWazuh] Starting AgentWazuh AI SOC Assistant on http://0.0.0.0:8000..."
python3 server.py
