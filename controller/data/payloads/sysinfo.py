import platform
import os
import sys
import socket
import subprocess
import json
import pwd
import grp
import time
import shutil

info = {
    "hostname": socket.gethostname(),
    "platform": platform.platform(),
    "uname": platform.uname()._asdict(),
    "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
    "uid": os.getuid(),
    "gid": os.getgid(),
    "cwd": os.getcwd(),
    "python": sys.version,
    "uptime": None,
    "cpu": None,
    "memory": None,
    "disk": None,
    "network": None,
    "processes": None,
    "users": None,
    "packages": None,
    "cron": None,
    "docker": None,
    "env_vars": {k: v for k, v in sorted(os.environ.items()) if not k.startswith("AWS_SECRET") and "SECRET" not in k and "KEY" not in k and "TOKEN" not in k and "PASSWORD" not in k},
    "sudo": None,
}

try:
    info["uptime"] = subprocess.run(["uptime"], capture_output=True, text=True, timeout=5).stdout.strip()
except Exception:
    pass

try:
    info["cpu"] = subprocess.run(["lscpu"], capture_output=True, text=True, timeout=10).stdout
except Exception:
    try:
        for line in open("/proc/cpuinfo"):
            if "model name" in line.lower():
                info["cpu"] = info.get("cpu", "") + line.strip() + "\n"
    except Exception:
        pass

try:
    mem = subprocess.run(["free", "-h"], capture_output=True, text=True, timeout=5)
    info["memory"] = mem.stdout
except Exception:
    pass

try:
    df = subprocess.run(["df", "-h"], capture_output=True, text=True, timeout=5)
    info["disk"] = df.stdout
except Exception:
    pass

try:
    iface = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=10)
    info["network"] = {"interfaces": iface.stdout}
    route = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
    info["network"]["route"] = route.stdout
    dns = open("/etc/resolv.conf").read()
    info["network"]["dns"] = dns
except Exception:
    try:
        iface = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
        info["network"] = {"interfaces": iface.stdout}
    except Exception:
        pass

try:
    ss = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=10)
    info["network"]["listening"] = ss.stdout
except Exception:
    try:
        netstat = subprocess.run(["netstat", "-tlnp"], capture_output=True, text=True, timeout=10)
        info["network"]["listening"] = netstat.stdout
    except Exception:
        pass

try:
    procs = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
    info["processes"] = procs.stdout
except Exception:
    try:
        procs = subprocess.run(["ps", "-ef"], capture_output=True, text=True, timeout=10)
        info["processes"] = procs.stdout
    except Exception:
        pass

try:
    info["users"] = [{"name": u.pw_name, "uid": u.pw_uid, "gid": u.pw_gid, "home": u.pw_dir, "shell": u.pw_shell} for u in pwd.getpwall() if u.pw_uid >= 1000 or u.pw_uid == 0]
except Exception:
    pass

try:
    if shutil.which("apt"):
        pkg = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, timeout=30)
        info["packages"] = {"manager": "apt", "list": pkg.stdout}
    elif shutil.which("rpm"):
        pkg = subprocess.run(["rpm", "-qa"], capture_output=True, text=True, timeout=30)
        info["packages"] = {"manager": "rpm", "list": pkg.stdout}
    elif shutil.which("pacman"):
        pkg = subprocess.run(["pacman", "-Q"], capture_output=True, text=True, timeout=30)
        info["packages"] = {"manager": "pacman", "list": pkg.stdout}
except Exception:
    pass

try:
    info["sudo"] = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, timeout=10).stdout.strip() or "no sudo -n available"
except Exception:
    info["sudo"] = "no passwordless sudo"

try:
    cron_users = []
    for u in pwd.getpwall():
        if u.pw_uid == 0 or u.pw_uid >= 1000:
            c = subprocess.run(["crontab", "-u", u.pw_name, "-l"], capture_output=True, text=True, timeout=5)
            if c.stdout.strip():
                cron_users.append({"user": u.pw_name, "cron": c.stdout.strip()})
    if os.path.exists("/etc/crontab"):
        cron_users.append({"user": "system", "cron": open("/etc/crontab").read().strip()})
    if os.path.isdir("/etc/cron.d"):
        for f in os.listdir("/etc/cron.d"):
            cron_users.append({"user": "cron.d/" + f, "cron": open(f"/etc/cron.d/{f}").read().strip()})
    info["cron"] = cron_users
except Exception:
    pass

try:
    docker = subprocess.run(["docker", "ps", "--no-trunc"], capture_output=True, text=True, timeout=10)
    info["docker"] = {"ps": docker.stdout}
    images = subprocess.run(["docker", "images", "--no-trunc"], capture_output=True, text=True, timeout=10)
    info["docker"]["images"] = images.stdout
except Exception:
    pass

print(json.dumps(info, indent=2, default=str))
