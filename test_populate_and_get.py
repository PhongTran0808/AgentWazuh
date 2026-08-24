import sys
sys.path.append(".")
import urllib3
urllib3.disable_warnings()

from services.wazuh_client import WazuhClient

wc = WazuhClient(
    host="192.168.1.234",
    port=55000,
    user="agentwazuh",
    password="1234567890gG@",
    dashboard_user="admin",
    dashboard_pass="admin"
)

alerts = wc.get_latest_alerts(limit=200, hours_back=720)
print("Fetched alerts count:", len(alerts))
if alerts:
    print("Sample Alert 1:", alerts[0].get("id"), "| Rule:", alerts[0].get("rule", {}).get("description"), "| Level:", alerts[0].get("rule", {}).get("level"), "| Agent:", alerts[0].get("agent", {}).get("name"))
