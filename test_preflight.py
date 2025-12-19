import socket
import sys
import os

# Add the project root to sys.path
sys.path.append(os.getcwd())

from strix.interface.utils import check_scanner_availability

# Port 5000 is currently active on this machine (AirPlay Receiver)
# So check_scanner_availability() should return True for port 5000
# if our fix to utils.py is working (it was 8080 before).

host = "host.docker.internal"
ip = socket.gethostbyname(host) if host != "localhost" else "127.0.0.1"
print(f"Testing {host} ({ip}) on port 5000...")

try:
    with socket.create_connection((ip, 5000), timeout=2.0):
        print("Success: Port 5000 is reachable via socket.create_connection")
except Exception as e:
    print(f"Failure: Port 5000 is NOT reachable: {e}")

is_available = check_scanner_availability()
print(f"check_scanner_availability() returned: {is_available}")

# Now test port 8080 (which should be False if nothing is there)
try:
    with socket.create_connection((ip, 8080), timeout=1.0):
        print("Port 8080 is reachable (unexpected for isolation test)")
except Exception:
    print("Port 8080 is NOT reachable (as expected)")

