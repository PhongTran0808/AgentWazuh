# ARCHITECTURE DECISIONS — CLOUD DUAL-TIER HA SYSTEM

## 1. 2000ms Polling Interval (Cluster DDoS Protection)
- **Decision**: Set `time.sleep(2.0)` (2000ms / 2 seconds) inside `middleware.py` background poller loop.
- **Rationale**: Eliminates Proxmox API socket exhaustion (`pvedaemon`/`pveproxy`) and prevents connection timeouts under cluster load.

## 2. Physical Host Crash Fencing & Direct Force NFS Lock Release
- **Decision**: In Active-Passive failover, if the target host SSH/ping times out (>3s), bypass `qm stop` CLI commands and forcibly release NFS disk locks on Node 3 (`/nfs/cloud-disks/`) via `fuser -k` or lock file purging.
- **Rationale**: Prevents fencing deadlocks when a physical node suffers a power outage or total network cut.

## 3. Active-Active Premium Package (Zero Downtime)
- **Decision**: Serve dual concurrent VM Console Tabs (`VM 100` and `VM 200`) in the frontend UI without auto-switching iframe overrides.
- **Rationale**: Gives customers full visibility and control over both machines. If one node fails, the customer uses the other machine console directly without any loading screens or page freeze.
