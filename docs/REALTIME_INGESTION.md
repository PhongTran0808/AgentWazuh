# Realtime ingestion: Wazuh Manager → AgentWazuh

AgentWazuh now supports three layers:

1. Wazuh custom integration calls `integrations/wazuh_webhook_forwarder.py` for each alert.
2. The AgentWazuh webhook merges the event, removes duplicates, and broadcasts it through SSE at `/api/events/alerts`.
3. Backend polling remains enabled as a recovery path when a webhook delivery fails.

For a local setup, start AgentWazuh on port `8000`, then configure the Wazuh Manager integration to invoke the copied script. The script expects the alert JSON file as its first argument:

```text
/var/ossec/integrations/custom-agentwazuh-webhook <alert-json-file>
```

Set these values in the Wazuh Manager environment or wrapper configuration:

```text
AGENTWAZUH_WEBHOOK_URL=http://127.0.0.1:8000/api/wazuh/webhook
WAZUH_WEBHOOK_TOKEN=<same value as AgentWazuh config/system_settings.json:webhook_token>
```

The browser does not poll for every event anymore. Dashboard and monitoring-map pages keep an SSE connection to `/api/events/alerts`; when a new alert arrives, they refresh their current view immediately. A slower periodic refresh remains as a fallback.

The API Inspector records the HTTP exchange, while the Evidence pane keeps the raw Wazuh event, the normalized Python record, and the AI analysis trace.
