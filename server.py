import threading
import socket
import sys
import signal
import math
import logging
import yaml

from security import *
from logging.handlers import TimedRotatingFileHandler

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S")

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)
log.addHandler(console_handler)

file_handler = TimedRotatingFileHandler("server.log", when="midnight", backupCount=5)
file_handler.namer = lambda name: name.replace(".log", "") + ".log"
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)

log.addHandler(console_handler)
log.addHandler(file_handler)

NUMBER_BYTES_HEADER = 4
MAX_CHUNKS = 2 ** (8*NUMBER_BYTES_HEADER) - 1
CHUNK_SIZE = 1024

class HandshakeError(Exception):
    pass

class Client():
    def __init__(self, sock, address, username, public_key, session_key, nonce):
        self.sock = sock
        self.address = address
        self.username = username
        self.public_key = public_key
        self.session_key = session_key
        self.nonce = nonce
        
class Server():
    def __init__(self, config_path="./server_config.yaml") -> None:
        config = self.load_config(config_path)
        self.host = config["server_ip"]
        self.port = config["server_port"]
        self.name = config["server_name"]
        self.rsa_passphrase = config["rsa_passphrase"].encode()
        self.private_key = None
        self.public_key = None
        self.server_socket = None
        self.clients = {}
        
        self.private_key, self.public_key = load_rsa_keys()
        if not all((self.private_key, self.public_key)):
            generate_rsa_keys(save=True)
        
        def sigint_handler(sig, frame):
            log.info("SIGINT received, closing the socket and exiting.")
            if self.server_socket:
                self.server_socket.close()
            for _, client in self.clients.items():
                client.sock.close()
            sys.exit(0)
        signal.signal(signal.SIGINT, sigint_handler)
        
    def load_config(self, path):
        with open(path) as f:
            return yaml.load(f, Loader=yaml.FullLoader)

    def dump_config(self, path, field ,value):
        config[field] = value
        with open(path, "w") as f:
            config = yaml.dump(config, stream=f, default_flow_style=False, sort_keys=False)
            
    
    # Start server and client threads
    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.settimeout(4) # handle blocked SIGINT on Win
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        log.info(f"Listenning on {self.host}:{self.port}.")

        while True:
            try:
                conn, address = self.server_socket.accept()
                thread = threading.Thread(target=self.client_thread, args=(conn, address), daemon = True)
                thread.start()
                log.info(f"New client {address}.")
            except socket.timeout:
                pass
    
    # Handle the client
    def client_thread(self, conn, address):
        try:
            client = self.handshake(conn, address, self.rsa_passphrase)
            while True:
                message, signature = self.receive(client)
                if not message:
                    break
                message = message.decode("utf-8")
                
                log.debug(f"New message from {client.username}: {message}")
                self.broadcast(client, message)
        except ConnectionResetError:
            log.info(f"Connection reset {address}.")
        except ConnectionAbortedError:
            pass
        except HandshakeError:
            log.critical(f"Error in handshake {address}.")
        except Exception as e:
            log.error(e)
        finally:
            conn.close()
            if address in self.clients:
                del self.clients[address]
                self.broadcast(None, f"{client.username} left the chat")
            log.info(f"Socket closed {address}.")

    # Handle connection
    def handshake(self, sock, address, passphrase: bytes):
        try:
            # Receive client public key
            data = sock.recv(CHUNK_SIZE)
            if not data:
                raise ConnectionResetError
            pubkey = import_key(data, passphrase)
            
            # Send session key
            session_key, nonce = generate_aes_key()
            data = encrypt_rsa(session_key + nonce, key=pubkey)
            sock.sendall(data)
            
            # Send public key
            pubkey = export_key(self.public_key)
            data, _ = encrypt_aes(key=session_key, nonce=nonce, data=pubkey)
            sock.sendall(data)
            
            # Receive and broadcast username
            data = sock.recv(CHUNK_SIZE)
            if not data:
                raise ConnectionResetError
            username = decrypt_aes(key=session_key, nonce=nonce, ciphertext=data)
            
            client = Client(sock, address, username.decode("utf-8"), pubkey, session_key, nonce)
            self.clients[address] = client
            self.broadcast(None, f"{client.username} joined the chat")
            return client
        except ValueError as e:
            raise HandshakeError

    # Broadcast a message to every clients except sender
    def broadcast(self, sender, message):
        for _, client in self.clients.items():
            # Don't send message to sender
            if sender and sender.address == client.address:
                continue
            
            try:
                formatted_message = f'{{"username":"{sender.username if sender else self.name}", "message":"{message}"}}'.encode("utf-8")
                self.send(client, formatted_message)
            except Exception as e:
                log.error(f"Error sending message to {client.username} {client.address}. {e}")

    # Send the whole message and end it with a double newline
    def send(self, client, message):
        message_hash = rsa_sign(self.private_key, message)
        num_chunks = math.ceil(len(message) / CHUNK_SIZE)
        encrypted_num_chunks, _ = encrypt_aes(client.session_key, client.nonce, num_chunks.to_bytes(4, byteorder='big'))
        
        client.sock.sendall(encrypted_num_chunks + message_hash)
        for i in range(0, len(message), CHUNK_SIZE):
            chunk = message[i:i + CHUNK_SIZE]
            encrypted_chunk, _ = encrypt_aes(client.session_key, client.nonce, chunk)
            client.sock.sendall(encrypted_chunk)

    # Retrieve data until a double newline
    def receive(self, client):
        message_header = client.sock.recv(256 + NUMBER_BYTES_HEADER)
        message_length = decrypt_aes(client.session_key, client.nonce, message_header[:4])
        message_length = int.from_bytes(message_length, byteorder='big')
        message_signature = message_header[NUMBER_BYTES_HEADER:]
        
        chunks = []
        for _ in range(message_length):
            chunk = client.sock.recv(CHUNK_SIZE)
            chunk = decrypt_aes(client.session_key, client.nonce, chunk)
            chunks.append(chunk)
        data = b"".join(chunks)
        
        return data, message_signature


if __name__ == "__main__":
    server = Server("./server_config.yaml")
    server.start()