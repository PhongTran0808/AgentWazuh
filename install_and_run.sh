#!/usr/bin/env bash
# ==============================================================================
# AgentWazuh 1-Click Auto-Installer & Launcher (Amazon Linux 2023 / RHEL / Ubuntu)
# Auto-detects Python 3.11+ for MCP & LangGraph compatibility
# ==============================================================================

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🚀 [AgentWazuh] Auto-detecting Python 3.11+ runtime...${NC}"

# Find best python binary (prefer python3.11 for Amazon Linux 2023 / RHEL)
if command -v python3.11 >/dev/null 2>&1; then
    PY_BIN="python3.11"
elif command -v python3.10 >/dev/null 2>&1; then
    PY_BIN="python3.10"
else
    if command -v dnf >/dev/null 2>&1; then
        echo -e "${YELLOW}📦 Installing python3.11 & python3.11-pip via dnf...${NC}"
        sudo dnf install -y python3.11 python3.11-pip 2>/dev/null
        if command -v python3.11 >/dev/null 2>&1; then
            PY_BIN="python3.11"
        else
            PY_BIN="python3"
        fi
    elif command -v apt-get >/dev/null 2>&1; then
        echo -e "${YELLOW}📦 Installing python3-pip via apt...${NC}"
        sudo apt-get update -qq && sudo apt-get install -y -qq python3-pip python3-venv 2>/dev/null
        PY_BIN="python3"
    else
        PY_BIN="python3"
    fi
fi

echo -e "${GREEN}✅ Using Python binary: $PY_BIN ($($PY_BIN --version 2>&1))${NC}"

# Ensure pip is available
if ! $PY_BIN -m pip --version >/dev/null 2>&1; then
    echo -e "${YELLOW}📦 Installing pip for $PY_BIN...${NC}"
    if command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3.11-pip python3-pip 2>/dev/null
    elif command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y python3-pip 2>/dev/null
    fi
fi

echo -e "${BLUE}📦 [AgentWazuh] Installing Python requirements from requirements.txt...${NC}"
$PY_BIN -m pip install -r requirements.txt --break-system-packages --quiet 2>/dev/null || $PY_BIN -m pip install -r requirements.txt

echo -e "${GREEN}✅ [AgentWazuh] Dependencies installed successfully!${NC}"
echo -e "${GREEN}⚡ Starting AgentWazuh AI SOC Assistant on http://0.0.0.0:8000...${NC}"
exec $PY_BIN server.py
