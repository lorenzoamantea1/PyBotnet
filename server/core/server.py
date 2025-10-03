import socket
import threading
import logging
from .hybrid import HybridCrypto
import uuid 

class Server:
    def __init__(self, host='127.0.0.1', port=547, debug=False):
        self.debug = debug
        self.host = host
        self.port = port

        self.logger = logging.getLogger("Server")
        self.logger.setLevel(logging.DEBUG if self.debug else logging.WARNING)

        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG if self.debug else logging.WARNING)
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%H:%M:%S'
        )
        ch.setFormatter(formatter)

        if not self.logger.handlers:
            self.logger.addHandler(ch)

        # Crypto
        self.crypto = HybridCrypto()
        self.private_key, self.public_key = self.crypto.generate_rsa_keys()

        # Clients
        self.clients = {}
        self.clients_lock = threading.Lock()

        # Socket
        self.server_socket = self._setup_server_socket()
        self.running = True

    # Setup 
    def _setup_server_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen()
        self.logger.info(f"Server listening on {self.host}:{self.port}")
        return sock

    # Main loop
    def run(self):
        self.logger.info(
            "Server RSA public key:\n" +
            self.crypto.serialize_public_key(self.public_key).decode()
        )
        try:
            while self.running:
                client_socket, addr = self.server_socket.accept()
                self.logger.info(f"New connection from {addr}")
                threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            self.logger.info("Server manually stopped")
        finally:
            self._shutdown()

    # Client handling
    def _handle_client(self, client_socket: socket.socket, addr):
        try:
            # Send server public key
            pubkey_pem = self.crypto.serialize_public_key(self.public_key)
            client_socket.send(len(pubkey_pem).to_bytes(2, 'big') + pubkey_pem)

            # Receive client public key
            length_bytes = client_socket.recv(2)
            if len(length_bytes) < 2:
                self._disconnect_client(client_socket, addr)
                return
            key_len = int.from_bytes(length_bytes, 'big')

            client_pubkey_pem = b''
            while len(client_pubkey_pem) < key_len:
                chunk = client_socket.recv(key_len - len(client_pubkey_pem))
                if not chunk:
                    raise ConnectionError("Incomplete client public key received")
                client_pubkey_pem += chunk

            client_pubkey = self.crypto.load_public_key(client_pubkey_pem)
            with self.clients_lock:
                client_id = str(uuid.uuid4())[:8]
                self.clients[client_socket] = {
                    "uuid": client_id,
                    "pubkey": client_pubkey
                }

            self.logger.info(f"Stored client public key for {addr}")

            # Keep connection alive
            client_socket.settimeout(10)
            while True:
                threading.Event().wait(1)

        except Exception as e:
            self.logger.warning(f"Client {addr} disconnected with error: {e}")
        finally:
            self._disconnect_client(client_socket, addr)

    def _disconnect_client(self, client_socket: socket.socket, addr):
        with self.clients_lock:
            self.clients.pop(client_socket, None)
        try:
            client_socket.close()
        except:
            pass
        self.logger.info(f"Client {addr} disconnected")

    # Messaging
    def send_to_all(self, message: str):
        with self.clients_lock:
            clients = list(self.clients.items())

        for client_socket, client_data in clients:
            try:
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

                # Wait for ACK
                length_bytes = self._recv_n_bytes(client_socket, 2)
                if not length_bytes:
                    raise ConnectionError("No ACK length received")
                ack_len = int.from_bytes(length_bytes, 'big')

                ack_encrypted = self._recv_n_bytes(client_socket, ack_len)
                if not ack_encrypted:
                    raise ConnectionError("No ACK payload received")

                ack = self.crypto.rsa_decrypt(self.private_key, ack_encrypted).decode()
                self.logger.info(f"ACK from {self._safe_addr(client_socket)}: {ack}")

            except Exception as e:
                addr = self._safe_addr(client_socket)
                self.logger.warning(f"Failed sending to client {addr}: {e}, disconneting..")
                self._disconnect_client(client_socket, addr)

    def send_to(self, client_socket: socket.socket, message: str):
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

            length_bytes = self._recv_n_bytes(client_socket, 2)
            if not length_bytes:
                raise ConnectionError("No ACK length received")
            ack_len = int.from_bytes(length_bytes, 'big')

            ack_encrypted = self._recv_n_bytes(client_socket, ack_len)
            if not ack_encrypted:
                raise ConnectionError("No ACK payload received")

            ack = self.crypto.rsa_decrypt(self.private_key, ack_encrypted).decode()
            self.logger.info(f"ACK from {self._safe_addr(client_socket)}: {ack}")

        except Exception as e:
            addr = self._safe_addr(client_socket)
            self.logger.warning(f"Failed sending to client {addr}: {e}, disconnecting..")
            self._disconnect_client(client_socket, addr)
    def _recv_n_bytes(self, sock, n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    # Utilities
    def get_clients(self):
        with self.clients_lock:
            return list(self.clients.items())

    def _safe_addr(self, client):
        try:
            return client.getpeername()
        except:
            return "unknown"

    # Shutdown
    def _shutdown(self):
        self.logger.info("Shutting down all client connections...")
        self.running = False
        with self.clients_lock:
            for client in list(self.clients.keys()):
                try:
                    client.close()
                except:
                    pass
            self.clients.clear()
        self.server_socket.close()
        self.logger.info("Server shut down.")

def runServer():
    server = Server()
    threading.Thread(target=server.run, daemon=True).start()
    return server
