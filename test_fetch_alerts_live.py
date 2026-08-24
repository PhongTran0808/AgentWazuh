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

print("1. Authenticate API 55000:", wc.authenticate())
print("2. Test Dashboard Session (443):", wc._get_dashboard_session() is not None)

alerts = wc.get_latest_alerts(limit=50, hours_back=24)
print("3. get_latest_alerts (hours_back=24) count:", len(alerts))

if len(alerts) == 0:
    print("4. Testing with hours_back=720 (30 days)...")
    alerts_30d = wc.get_latest_alerts(limit=50, hours_back=720)
    print("5. get_latest_alerts (30 days) count:", len(alerts_30d))

