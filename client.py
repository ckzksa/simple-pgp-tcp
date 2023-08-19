import socket
import threading
import logging
import math
import rich
import json

from collections import namedtuple
from rich.prompt import Prompt
from security import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S")

file_handler = logging.FileHandler("client.log", mode='w')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
log.addHandler(file_handler)

NUMBER_BYTES_HEADER = 4
MAX_CHUNKS = 2 ** (8*NUMBER_BYTES_HEADER) - 1
CHUNK_SIZE = 1024

class HandshakeError(Exception):
    pass

AesKey = namedtuple('AesKey', ['key', 'nonce'])

class Client():
    def __init__(self, host, port) -> None:
        self.host = host
        self.port = port
        self.client_socket = None
        self.private_key = None
        self.public_key = None
        self.server_public_key = None
        self.e2e_key = None
        self.session_key = None
        self.nonce = None
        self.username = ""
        
        self.private_key, self.public_key = load_rsa_keys()
        if not all((self.private_key, self.public_key)):
            generate_rsa_keys(save=True)
        
    def start(self, e2e_encryption=False):
        try:
            while not self.username:
                self.username = Prompt.ask("[bold green]Username[/bold green]")
            
            if e2e_encryption:
                password = ""
                while not password:
                    password = Prompt.ask("[bold green]End-to-end password[/bold green]")
                password = sha_512(password.encode())
                self.e2e_key = AesKey(password[:32], password[32:])
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            
            self.handshake(self.client_socket, b"verystrongpassword")
            
            log.debug(f"Connected to server {self.host} : {self.port}.")
            print(f"Connected to server {self.host} : {self.port}.")
            
            send_thread = threading.Thread(target=self.client_send, daemon = True)
            receive_thread = threading.Thread(target=self.client_receive, daemon = True)
            send_thread.start()
            receive_thread.start()
            
            send_thread.join()
            receive_thread.join()
        except KeyboardInterrupt:
            log.info("SIGINT received, closing the socket and exiting.")
        except HandshakeError:
            log.critical("Error in handshake.")
        except Exception as e:
            log.error(e)
        finally:
            if client.client_socket:
                client.client_socket.close()

    # Handle connection
    def handshake(self, sock, passphrase: bytes=None):
        try:
            # Send public key
            pubkey = export_key(self.public_key, passphrase=passphrase)
            sock.sendall(pubkey)
            
            # Receive session key
            data = sock.recv(CHUNK_SIZE)
            data = decrypt_rsa(data, key=self.private_key)
            self.session_key = data[:16]
            self.nonce = data[16:]
            
            # Receive server public key
            data = sock.recv(CHUNK_SIZE)
            if not data:
                raise ConnectionResetError
            data = decrypt_aes(key=self.session_key, nonce=self.nonce, ciphertext=data)
            self.server_public_key = import_key(data)
            
            # Send username
            data, _ = encrypt_aes(key=self.session_key, nonce=self.nonce, data=self.username.encode("utf-8"))
            sock.sendall(data)
        except:
            raise HandshakeError

    def client_send(self):
        try:
            while True:
                message = ""
                while not message:
                    rich.print(f"<[bold violet]{self.username}[/bold violet]> ", end='')
                    message = input()
                    
                if not message:
                    pass
                else:
                    message = message.encode("utf-8")
                    if self.e2e_key:
                        message, _ = encrypt_aes(key=self.e2e_key.key, nonce=self.e2e_key.nonce, data=message)
                        message = message.hex().encode("utf-8")
                    self.send(message)
        except EOFError:
            pass
        except Exception as e:
            log.error(e)

    def client_receive(self):
        try:
            while True:
                message, signature = self.receive()
                message = json.loads(message.decode('utf-8'))
                username = message["username"]
                message = message["message"]
                if self.e2e_key and username != "SERVER":
                    message = bytes.fromhex(message)
                    message = decrypt_aes(self.e2e_key.key, self.e2e_key.nonce, message).decode('utf-8')
                print(f"<{username}> {message}")
        except ConnectionResetError:
            print("Connection reset by host.")
            log.info(f"Connection reset by host.")
        except ConnectionAbortedError:
            log.info(f"Connection aborted.")
        except HandshakeError:
            log.critical(f"Error in handshake.")
        except Exception as e:
            log.error(e)

    def send(self, message):
        message_hash = rsa_sign(self.private_key, message)
        num_chunks = math.ceil(len(message) / CHUNK_SIZE)
        encrypted_num_chunks, _ = encrypt_aes(self.session_key, self.nonce, num_chunks.to_bytes(4, byteorder='big'))
        self.client_socket.sendall(encrypted_num_chunks + message_hash)
        
        for i in range(0, len(message), CHUNK_SIZE):
            chunk = message[i:i + CHUNK_SIZE]
            encrypted_chunk, _ = encrypt_aes(self.session_key, self.nonce, chunk)
            self.client_socket.sendall(encrypted_chunk)

    def receive(self):
        message_header = self.client_socket.recv(256 + NUMBER_BYTES_HEADER)
        message_length = decrypt_aes(self.session_key, self.nonce, message_header[:4])
        message_length = int.from_bytes(message_length, byteorder='big')
        message_signature = message_header[NUMBER_BYTES_HEADER:]
        
        chunks = []
        for _ in range(message_length):
            chunk = self.client_socket.recv(CHUNK_SIZE)
            chunk = decrypt_aes(self.session_key, self.nonce, chunk)
            chunks.append(chunk)
        data = b"".join(chunks)
        
        return data, message_signature

if __name__ =="__main__":
    client = Client("127.0.0.1", 4321)
    client.start(e2e_encryption=True)
