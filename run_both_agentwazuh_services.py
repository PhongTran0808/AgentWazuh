import subprocess, time, sys, os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

print("=================================================================")
print("🛡️ LAUNCHING AGENTWAZUH DUAL SERVICES (PORTS 8080 & 9090)")
print("   Port 8080: SOC AI Incident Assistant Web Dashboard")
print("   Port 9090: WazuhSim Live Network Map & Log Streamer")
print("=================================================================")

# Kill any existing processes on 8080 and 9090
subprocess.run("fuser -k -9 8080/tcp 2>/dev/null || true", shell=True)
subprocess.run("fuser -k -9 9090/tcp 2>/dev/null || true", shell=True)
time.sleep(1)

# Start 8080
p8080 = subprocess.Popen([sys.executable, str(BASE_DIR / "server.py")], cwd=str(BASE_DIR))
print(f"🟢 Started AgentWazuh Core (Port 8080) - PID: {p8080.pid}")

# Start 9090
p9090 = subprocess.Popen([sys.executable, str(BASE_DIR / "server_9090.py")], cwd=str(BASE_DIR))
print(f"🟢 Started WazuhSim Streamer (Port 9090) - PID: {p9090.pid}")

time.sleep(3)

# Keep parent process alive
try:
    p8080.wait()
    p9090.wait()
except KeyboardInterrupt:
    print("\nStopping AgentWazuh services...")
    p8080.terminate()
    p9090.terminate()
