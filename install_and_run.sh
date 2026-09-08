#!/usr/bin/env bash
# ==============================================================================
# AgentWazuh 1-Click Installer & Launcher
# ==============================================================================

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🚀 [AgentWazuh] Checking and installing system packages...${NC}"
if ! command -v pip3 >/dev/null 2>&1; then
    echo -e "${BLUE}📦 Installing python3-pip...${NC}"
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y -qq python3-pip
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3-pip
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y python3-pip
    fi
fi

echo -e "${BLUE}📦 [AgentWazuh] Installing Python requirements...${NC}"
python3 -m pip install -r requirements.txt --break-system-packages --quiet 2>/dev/null || pip3 install -r requirements.txt --quiet

echo -e "${GREEN}✅ [AgentWazuh] Dependencies installed successfully!${NC}"
echo -e "${GREEN}⚡ Starting AgentWazuh AI SOC Assistant on http://0.0.0.0:8000...${NC}"
exec python3 server.py
