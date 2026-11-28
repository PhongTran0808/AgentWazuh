# SOC REASONING & ACTIVE EVIDENCE HUNTING POLICY

## 1. Multi-Stage Threat Recognition (Recall & Precision)
- **Never judge an isolated log line in a vacuum.** Always evaluate events in causal sequence across devices:
  - **Perimeter + DMZ Correlation:** A successful login (`SSH Accepted` / Web Admin `200 OK`) occurring shortly after brute-force/scanning bursts from the **same source IP** OR from an **unseen IP outside normal login baseline** MUST be classified as a confirmed compromise (`CRITICAL`), never as benign login.
  - **Cross-Zone Lateral Movement (T1021):** Unexpected administrative/file-sharing connections (SMB, RDP, SSH, DB) initiated from a public-facing DMZ host toward internal LAN/server zones require immediate escalation.
  - **Endpoint Malware Chain:** When a suspicious executable/file appears on an endpoint, correlate all three forensic links before concluding: **File Path/Source -> File Hash (MD5/SHA-256) & Process -> Persistence Mechanism (Registry / Service / Scheduled Task)**.
- **False-Positive Guard:** Cross-check against trusted management/SOC zones and routine OS/service telemetry (e.g., authorized SOC admin `publickey` SSH, uptime `/healthcheck`, normal DNS/Windows Update) so benign operations are not escalated as attacks.

## 2. Active Evidence Hunting Protocol (MCP Tool Usage)
- When current alert context is incomplete or ambiguous (e.g., a single `SSH Accepted` event or lone firewall alert without prior history):
  1. **Do NOT guess or fabricate** missing timeline events, IPs, Rule IDs, or timestamps.
  2. **Actively fetch more logs** using available MCP / Wazuh tools (`search_correlated_events`, `search_alerts`, `get_agents`, `get_manager_status`) across an expanded time window for the relevant IP or Agent.
  3. **Synthesize only verified evidence** and present actionable recommendations under Human-in-the-Loop (HITL) governance.
