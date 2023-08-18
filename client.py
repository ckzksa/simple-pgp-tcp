import socket
import threading
import signal
import logging
import rich

from rich.prompt import Prompt
from security import *

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S")

file_handler = logging.FileHandler("client.log", mode='w')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
log.addHandler(file_handler)

SERVER = "127.0.0.1"
PORT = 4321

class HandshakeError(Exception):
    pass

class Client():
    def __init__(self) -> None:
        self.client_socket = None
        self.private_key = None
        self.public_key = None
        self.session_key = None
        self.nonce = None
        self.username = ""
        
        self.private_key, self.public_key = load_rsa_keys()
        if not all((self.private_key, self.public_key)):
            generate_rsa_keys(save=True)
        
    def start(self):
        try:
            while not self.username:
                self.username = Prompt.ask("[bold green]Username[/bold green]")
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((SERVER, PORT))
            
            self.handshake(self.client_socket, b"verystrongpassword")
            
            log.debug(f"Connected to server {SERVER} : {PORT}.")
            print(f"Connected to server {SERVER} : {PORT}.")
            
            send_thread = threading.Thread(target=self.client_send, args = (self.client_socket,), daemon = True)
            receive_thread = threading.Thread(target=self.client_receive, args = (self.client_socket,), daemon = True)
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
            # send public key
            pubkey = export_key(self.public_key, passphrase=passphrase)
            self.send(sock, pubkey)
            
            # receive session key
            data = self.receive(sock)
            data = decrypt_rsa(data, key=self.private_key)
            self.session_key = data[:16]
            self.nonce = data[16:]
            
            # send username
            data, _ = encrypt_aes(key=self.session_key, nonce=self.nonce, payload=self.username.encode("utf-8"))
            self.send(sock, data)
        except:
            raise HandshakeError

    def client_send(self, client_socket):
        try:
            while True:
                payload = ""
                while not payload:
                    rich.print(f"<[bold violet]{self.username}[/bold violet]> ", end='')
                    payload = input()
                    
                if not payload:
                    pass
                else:
                    payload, _ = encrypt_aes(self.session_key, self.nonce, payload.encode("utf-8"))
                    self.send(client_socket, payload)
                    
        except EOFError:
            pass
        except Exception as e:
            log.error(e)

    def client_receive(self, client_socket):
        try:
            while True:
                payload = self.receive(client_socket)
                payload = decrypt_aes(key=self.session_key, nonce=self.nonce, ciphertext=payload)
                print(f"{payload.decode('utf-8')}")
        except ConnectionResetError:
            print("Connection reset by host.")
            log.info(f"Connection reset by host.")
        except ConnectionAbortedError:
            log.info(f"Connection aborted.")
        except HandshakeError:
            log.critical(f"Error in handshake.")
        except Exception as e:
            log.error(e)

    def send(self, sock, payload):
        sock.sendall(payload + b"\n\n")

    def receive(self, sock):
        payload = b""
        
        while not payload.endswith(b"\n\n"):
            data = sock.recv(1024)
            if not data:
                return None
            payload = payload + data
        
        return payload[:-2]

if __name__ =="__main__":
    client = Client()
    client.start()
