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
    def __init__(self, peers, debug=False):
        self.peers = peers
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

    #  Connect to a peer 
    def connect_to_peer(self, host, port):
        try:
            # Connect socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))

            # Receive peer public key
            key_len_bytes = self.receive_bytes(client_socket, 2)
            if not key_len_bytes:
                raise ConnectionError("Failed to receive peer key length")
            key_len = int.from_bytes(key_len_bytes, 'big')

            peer_pubkey_pem = self.receive_bytes(client_socket, key_len)
            if not peer_pubkey_pem:
                raise ConnectionError("Failed to receive peer key")
            peer_pubkey = self.crypto.load_public_key(peer_pubkey_pem)

            # Send own public key
            pubkey_pem = self.crypto.serialize_public_key(self.public_key)
            client_socket.send(len(pubkey_pem).to_bytes(2, 'big') + pubkey_pem)

            # Authenticate as C2
            auth_msg = json.dumps({"role": "C2"}).encode()
            signature = self.crypto.sign(self.private_key, auth_msg)
            auth_payload = json.dumps({"role": "C2", "signature": signature.hex()}).encode()
            client_socket.send(len(auth_payload).to_bytes(2, 'big') + auth_payload)

            # Store connection
            peer_id = str(uuid.uuid4())[:8]
            with self.connections_lock:
                self.connections[peer_id] = {
                    "socket": client_socket,
                    "host": host,
                    "port": port,
                    "pubkey": peer_pubkey
                }

            self.logger.info(f"Connected to peer {host}:{port}")
            return peer_id

        except Exception as e:
            self.logger.error(f"Failed to connect to {host}:{port}: {e}")
            return None

    #  Setup all peers 
    def setup_sockets(self):
        self.running = True
        for host, port in self.peers:
            peer_id = self.connect_to_peer(host, port)
            if peer_id:
                # Start a thread for each peer
                threading.Thread(target=self.handle_connection, args=(peer_id,), daemon=True).start()

    #  Handle a peer 
    def handle_connection(self, peer_id):
        try:
            while self.running:
                # Idle loop, can be extended for receiving messages
                threading.Event().wait(1)
        except Exception as e:
            self.logger.error(f"Error in connection to peer {peer_id}: {e}")
        finally:
            self.disconnect_peer(peer_id)

    #  Send to all peers 
    def send_to_all(self, message):
        with self.connections_lock:
            peers = list(self.connections.items())
        if not peers:
            self.logger.warning("No peers connected")
            return

        for peer_id, peer_data in peers:
            self.send_to(peer_id, message)

    #  Send to one peer 
    def send_to(self, peer_id, message):
        try:
            with self.connections_lock:
                peer_data = self.connections.get(peer_id)
                if not peer_data:
                    raise ConnectionError(f"Peer {peer_id} not connected")

            client_socket = peer_data["socket"]
            message_bytes = message.encode()
            signature = self.crypto.sign(self.private_key, message_bytes)

            # Send message and signature
            client_socket.send(len(message_bytes).to_bytes(2, 'big') + message_bytes)
            client_socket.send(len(signature).to_bytes(2, 'big') + signature)

            self.logger.info(f"Sent message to peer {peer_id}: {message}")

        except Exception as e:
            self.logger.warning(f"Failed to send to peer {peer_id}: {e}")
            self.disconnect_peer(peer_id)

    #  Receive fixed bytes 
    def receive_bytes(self, sock, n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    #  Get list of peers 
    def get_peers(self):
        with self.connections_lock:
            return [(peer_id, d["host"], d["port"]) for peer_id, d in self.connections.items()]

    #  Disconnect a peer 
    def disconnect_peer(self, peer_id):
        with self.connections_lock:
            if peer_id in self.connections:
                try:
                    self.connections[peer_id]["socket"].close()
                except:
                    pass
                del self.connections[peer_id]
                self.logger.info(f"Disconnected peer {peer_id}")

    #  Shutdown all connections 
    def shutdown(self):
        self.logger.info("Shutting down all peer connections")
        self.running = False
        with self.connections_lock:
            for peer_id in list(self.connections.keys()):
                self.disconnect_peer(peer_id)
        self.logger.info("All connections shut down")
