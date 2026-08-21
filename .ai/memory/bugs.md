# BUGS & FIXES LOG - AGENTWAZUH

## BUG-001: Web UI Settings Save 502 Bad Gateway
- **Status**: FIXED
- **Root Cause**: `update_settings` in `core/server.py` attempted to connect to Wazuh using admin/admin without JWT or threw HTTP 502 blocking saving system configuration.
- **Fix**: Updated `update_settings` to use readonly user `agentwazuh`, fallback gracefully, and allow saving `SYSTEM_SETTINGS` into `config/system_settings.json` without throwing 502 exceptions.

## BUG-002: ModuleNotFoundError in IncidentAssistant
- **Status**: FIXED
- **Root Cause**: `services/incident_assistant.py` attempted `from correlation_engine import ...` instead of `from services.correlation_engine import ...`.
- **Fix**: Fixed relative imports across all services modules to use modular package names (`services.correlation_engine`, `services.wazuh_client`).

## BUG-003: UTC Timestamp Offset Misalignment on Web UI
- **Status**: FIXED
- **Root Cause**: OpenSearch stores raw alert timestamps in UTC (`10:21:31`). `web/app.js` and `web/drilldown.js` rendered timestamps using `substring(11, 19)` directly without converting to local time zone (UTC+7 / ICT).
- **Fix**: Added `formatLocalTime(tsStr)` in frontend JS to format timestamps to local ICT time (`17:21:31`).
