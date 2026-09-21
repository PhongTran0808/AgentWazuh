#!/usr/bin/env python3
"""Forward one Wazuh JSON alert to the local AgentWazuh webhook.

Copy this file to Wazuh Manager's integrations directory as a custom
integration. Wazuh passes the alert JSON file as argv[1]. The script uses only
the Python standard library so it can run in the Wazuh runtime environment.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


WEBHOOK_URL = os.getenv("AGENTWAZUH_WEBHOOK_URL", "http://127.0.0.1:8000/api/wazuh/webhook")
WEBHOOK_TOKEN = os.getenv("WAZUH_WEBHOOK_TOKEN", "")


def main() -> int:
    if len(sys.argv) < 2:
        print("missing Wazuh alert JSON path", file=sys.stderr)
        return 2

    alert_path = Path(sys.argv[1])
    token = sys.argv[2] if len(sys.argv) > 2 else WEBHOOK_TOKEN
    if not token:
        print("missing WAZUH_WEBHOOK_TOKEN", file=sys.stderr)
        return 2

    try:
        payload = json.loads(alert_path.read_text(encoding="utf-8"))
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = Request(
            WEBHOOK_URL,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-AgentWazuh-Token": token,
            },
        )
        with urlopen(request, timeout=3) as response:
            if response.status < 200 or response.status >= 300:
                print(f"AgentWazuh webhook returned HTTP {response.status}", file=sys.stderr)
                return 1
        return 0
    except (OSError, ValueError, HTTPError, URLError) as exc:
        print(f"AgentWazuh webhook forwarding failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
