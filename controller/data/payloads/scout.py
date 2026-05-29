import json
import socket
import subprocess
import os
import struct
import fcntl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network, ip_address

results = {
    "hostname": socket.gethostname(),
    "local_ips": [],
    "arp_table": None,
    "local_ports": [],
    "reachable_hosts": [],
    "gateway": None,
}

try:
    SIOCGIFCONF = 0x8912
    SIOCGIFADDR = 0x8915
    MAX_BYTES = 4096
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifconf = struct.pack("iL", MAX_BYTES, 0)
    out = fcntl.ioctl(s.fileno(), SIOCGIFCONF, ifconf)
    out_bytes = out[:struct.calcsize("iL") + MAX_BYTES]
    out_len = struct.unpack("iL", out[:struct.calcsize("iL")])[0]
    interfaces = []
    i = struct.calcsize("iL")
    while i < out_len:
        ifr_name = out_bytes[i:i+16].split(b'\0')[0].decode()
        ifr_addr = out_bytes[i+20:i+24]
        ip = socket.inet_ntoa(ifr_addr)
        if ip != "0.0.0.0":
            results["local_ips"].append(ip)
        i += 32
    s.close()
except Exception:
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        results["local_ips"] = out.stdout.strip().split()
    except Exception:
        pass

try:
    arp = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
    results["arp_table"] = arp.stdout
except Exception:
    try:
        arp = open("/proc/net/arp").read()
        results["arp_table"] = arp
    except Exception:
        pass

try:
    route = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
    results["gateway"] = route.stdout.strip()
except Exception:
    pass

def _check_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        r = s.connect_ex((host, port))
        s.close()
        if r == 0:
            return port
    except Exception:
        pass
    return None

local_scan = []
results["local_ports"] = [p for p in (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 6443, 8080, 8443, 9000, 9090, 11211, 27017) if _check_port("127.0.0.1", p)]

for ip_str in results["local_ips"][:3]:
    try:
        net = ip_address(ip_str)
        base = ".".join(ip_str.split(".")[:3])
        reachable = []
        def _ping(host):
            r = subprocess.run(["ping", "-c1", "-W1", host], capture_output=True, timeout=3)
            return host if r.returncode == 0 else None
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(_ping, f"{base}.{i}"): i for i in range(1, 255)}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    reachable.append(r)
        results["reachable_hosts"] = reachable
        break
    except Exception:
        pass

print(json.dumps(results, indent=2, default=str))
