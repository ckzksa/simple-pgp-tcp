import threading
import socket
import sys
import signal
import logging

from security import Security
from logging.handlers import TimedRotatingFileHandler

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S")

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
log.addHandler(console_handler)

file_handler = TimedRotatingFileHandler("server.log", when="midnight", backupCount=5)
file_handler.namer = lambda name: name.replace(".log", "") + ".log"
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)

log.addHandler(console_handler)
log.addHandler(file_handler)

HOST = "0.0.0.0"
PORT = 4321

class HandshakeError(Exception):
    pass

class Client():
    def __init__(self, sock, address, username, pubkey, session_key, nonce):
        self.sock = sock
        self.address = address
        self.username = username
        self.pubkey = pubkey
        self.session_key = session_key
        self.nonce = nonce
        
class Server():
    def __init__(self, host, port) -> None:
        self.host = host
        self.port = port
        self.security = Security(save_keys=True)
        self.server_socket = None
        self.clients = {}
        
        def sigint_handler(sig, frame):
            log.info("SIGINT received, closing the socket and exiting.")
            if self.server_socket:
                self.server_socket.close()
            for _, client in self.clients.items():
                client.sock.close()
            sys.exit(0)
        signal.signal(signal.SIGINT, sigint_handler)
    
    # start server and client threads
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
                log.debug(f"Timeout.")
                pass
    
    # Handle the client
    def client_thread(self, conn, address):
        try:
            client = self.handshake(conn, address, b"verystrongpassword")
            while True:
                payload = self.receive(conn)
                if not payload:
                    break
                
                payload = self.security.decrypt_aes(key=client.session_key, nonce=client.nonce, ciphertext=payload)
                payload = payload.decode('utf-8')
                log.debug(f"New message from {client.username}: {payload}.")
                self.broadcast(client, payload)
        except ConnectionResetError:
            log.info(f"Connection reset {address}.")
        except ConnectionAbortedError:
            pass
        except HandshakeError:
            log.critical(f"Error in handshake {address}.")
        except Exception as e:
            print(type(e))
            log.error(e)
        finally:
            conn.close()
            if address in self.clients:
                del self.clients[address]
                self.broadcast(None, f"{client.username} left the chat")
            log.info(f"Socket closed {address}.")

    # Handle connection
    def handshake(self, sock, address, passphrase: bytes):#TODO clear le code
        try:
            # receive client public key
            data = self.receive(sock)
            if not data:
                raise ConnectionResetError
            pubkey = self.security.import_key(data, passphrase)
            
            # send session key
            session_key, nonce = self.security.generate_aes_key()
            data = self.security.encrypt_rsa(session_key + nonce, key=pubkey)
            self.send(sock, data)
            
            #receive and broadcast username
            data = self.receive(sock)
            if not data:
                raise ConnectionResetError
            username = self.security.decrypt_aes(key=session_key, nonce=nonce, ciphertext=data)
            
            client = Client(sock, address, username.decode('utf-8'), pubkey, session_key, nonce)
            self.clients[address] = client
            self.broadcast(None, f"{client.username} joined the chat")
            
            return client
        except ValueError as e:
            raise HandshakeError

    # broadcast a message to every clients except sender
    def broadcast(self, sender, payload):
        for _, client in self.clients.items():
            # don't send message to sender
            if sender and sender.address == client.address:
                continue
            
            try:
                enc_payload, _ = self.security.encrypt_aes(client.session_key,
                                                    client.nonce,
                                                    f"<{sender.username if sender else 'SERVER'}> {payload}".encode("utf-8"))
                self.send(client.sock, enc_payload)
            except Exception as e:
                log.error(f"Error sending message to {client.username} {client.address}. {e}")

    # send the whole message and end it with a double newline
    def send(self, sock, payload):
        sock.sendall(payload + b"\n\n")

    # retrieve data until a double newline
    def receive(self, sock):
        payload = b""
        
        while not payload.endswith(b"\n\n"): #TODO changer ca, risque faible d'erreur
            data = sock.recv(1024)
            if not data:
                return None
            payload = payload + data
        
        return payload[:-2]


if __name__ == "__main__":
    server = Server(HOST, PORT)
    server.start()