import socket
import threading
import logging
import uuid
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .crypto import Crypto
from .logger import LoggerFormatter

class C2Client:
    def __init__(self, nodes, debug=False):
        self.nodes = nodes
        self.debug = debug
        self.running = False
        self.connections = {}
        self.connections_lock = threading.Lock()
    
        # Logger setup
        self.logger = logging.getLogger("C2Client")
        self.logger.setLevel(logging.DEBUG if debug else logging.WARNING)
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG if debug else logging.WARNING)
            ch.setFormatter(LoggerFormatter())
            self.logger.addHandler(ch)

        # Crypto setup
        self.crypto = Crypto()
        self.private_key, self.public_key = self.crypto.load_rsa_keys()

    # --- Connection Management ---

    #  Setup all nodes 
    def setup_sockets(self):
        self.running = True
        for host, port in self.nodes:
            node_id = self.connect_to_node(host, port)
            if node_id:
                # Start a thread for each node
                threading.Thread(target=self.handle_connection, args=(node_id,), daemon=True).start()

    #  Connect to a node 
    def connect_to_node(self, host, port):
        client_socket = None
        try:
            # Connect socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)  # Set timeout for connection and response
            client_socket.connect((host, port))

            # Receive node public key
            key_len_bytes = self.receive_bytes(client_socket, 2)
            if not key_len_bytes:
                raise ConnectionError("Failed to receive node key length")
            key_len = int.from_bytes(key_len_bytes, 'big')

            node_pubkey_pem = self.receive_bytes(client_socket, key_len)
            if not node_pubkey_pem:
                raise ConnectionError("Failed to receive node key")
            node_pubkey = self.crypto.load_public_key(node_pubkey_pem)

            # Send own public key
            pubkey_pem = self.crypto.serialize_public_key(self.public_key)
            client_socket.send(len(pubkey_pem).to_bytes(2, 'big') + pubkey_pem)
            self.logger.debug(f"Sent public key to {host}:{port}")

            # Authenticate as C2
            auth_msg = json.dumps({"role": "C2"}).encode()
            signature = self.crypto.sign(self.private_key, auth_msg)
            auth_payload = json.dumps({"role": "C2", "signature": signature.hex()}).encode()
            client_socket.send(len(auth_payload).to_bytes(2, 'big') + auth_payload)
            self.logger.debug(f"Sent auth payload to {host}:{port}: {auth_payload.decode()}")

            # Receive confirmation from node
            length_bytes = self.receive_bytes(client_socket, 2)
            if not length_bytes:
                raise ConnectionError("Failed to receive confirmation length")
            confirm_len = int.from_bytes(length_bytes, 'big')
            confirm_message = self.receive_bytes(client_socket, confirm_len)
            if not confirm_message:
                raise ConnectionError("Failed to receive confirmation message")
            
            confirm_data = json.loads(confirm_message.decode())
            self.logger.debug(f"Received confirmation from {host}:{port}: {confirm_data}")
            if confirm_data.get("status") != "success":
                error_msg = confirm_data.get("message", "No error message provided")
                raise ConnectionError(f"Node rejected connection: {error_msg}")

            # Store connection
            node_id = str(uuid.uuid4())[:8]
            with self.connections_lock:
                self.connections[node_id] = {
                    "socket": client_socket,
                    "host": host,
                    "port": port,
                    "pubkey": node_pubkey
                }

            self.logger.info(f"\x1b[38;5;46;48;5;22mConnected to node :: {host}:{port}\x1b[0m")
            return node_id

        except socket.timeout:
            self.logger.error(f"Timeout connecting to {host}:{port}")
            if client_socket:
                try:
                    client_socket.close()
                except:
                    pass
            return None
        except ConnectionResetError:
            self.logger.error(f"Connection reset by {host}:{port}")
            if client_socket:
                try:
                    client_socket.close()
                except:
                    pass
            return None
        except Exception as e:
            self.logger.error(f"Failed to connect to {host}:{port}: {e}")
            if client_socket:
                try:
                    client_socket.close()
                except:
                    pass
            return None

    #  Handle a node 
    def handle_connection(self, node_id):
        try:
            while self.running:
                # Idle loop, can be extended for receiving messages
                threading.Event().wait(1)
        except Exception as e:
            self.logger.error(f"Error in connection to node {node_id}: {e}")
        finally:
            self.disconnect_node(node_id)

    #  Disconnect a node 
    def disconnect_node(self, node_id):
        with self.connections_lock:
            if node_id in self.connections:
                try:
                    self.connections[node_id]["socket"].close()
                except:
                    pass
                del self.connections[node_id]
                self.logger.info(f"Disconnected node {node_id}")

    #  Shutdown all connections 
    def shutdown(self):
        self.logger.info("Shutting down all node connections")
        self.running = False
        with self.connections_lock:
            for node_id in list(self.connections.keys()):
                self.disconnect_node(node_id)
        self.logger.info("All connections shut down")

    # --- Messaging ---

    #  Send to one node 
    def send_to(self, node_id, message):
        try:
            with self.connections_lock:
                node_data = self.connections.get(node_id)
                if not node_data:
                    raise ConnectionError(f"node {node_id} not connected")

            client_socket = node_data["socket"]
            message_bytes = message.encode()
            signature = self.crypto.sign(self.private_key, message_bytes)

            # Send message and signature
            client_socket.send(len(message_bytes).to_bytes(2, 'big') + message_bytes)
            client_socket.send(len(signature).to_bytes(2, 'big') + signature)

            self.logger.info(f"Sent message to node {node_id}: {message}")

        except Exception as e:
            self.logger.warning(f"Failed to send to node {node_id}: {e}")
            self.disconnect_node(node_id)

    #  Send to all nodes 
    def send_to_all(self, message):
        with self.connections_lock:
            nodes = list(self.connections.items())
        if not nodes:
            self.logger.warning("No nodes connected")
            return

        for node_id, _ in nodes:
            self.send_to(node_id, message)

    # --- Utility Methods ---

    #  Receive fixed bytes 
    def receive_bytes(self, sock, n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    #  Get list of nodes 
    def get_nodes(self):
        with self.connections_lock:
            return [(node_id, d["host"], d["port"]) for node_id, d in self.connections.items()]