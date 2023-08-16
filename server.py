import threading
import socket
import sys
import signal
import logging

from security import Security
from logging.handlers import TimedRotatingFileHandler

#TODO utiliser select

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

security = Security(save_keys=True)
server_socket = None
clients = {}

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

# broadcast a message to every clients except sender
def broadcast(sender, payload):
    for _, client in clients.items():
        # don't send message to sender
        if sender and sender.address == client.address:
            continue
        
        try:
            enc_payload, _ = security.encrypt_aes(client.session_key,
                                                  client.nonce,
                                                  f"<{sender.username if sender else 'SERVER'}> {payload}".encode("utf-8"))
            send(client.sock, enc_payload)
        except Exception as e:
            log.error(f"Error sending message to {client.username} {client.address}. {e}")

# Handle the client
def client_thread(conn, address):
    try:
        client = handshake(conn, address)
        while True:
            payload = receive(conn)
            if not payload:
                break
            
            payload = security.decrypt_aes(key=client.session_key, nonce=client.nonce, ciphertext=payload)
            payload = payload.decode('utf-8')
            log.debug(f"New message from {client.username}: {payload}.")
            broadcast(client, payload)
    except ConnectionResetError:
        log.info(f"Connection reset {address}.")
    except ConnectionAbortedError:
        pass
    except HandshakeError:
        log.error(f"Error in handshake {address}.")
    except Exception as e:
        log.error(e)
    finally:
        conn.close()
        del clients[address]
        log.info(f"Socket closed {address}.")
        broadcast(None, f"{client.username} left the chat")

# send the whole message and end it with a double newline
def send(sock, payload):
    sock.sendall(payload + b"\n\n")

# retrieve data until a double newline
def receive(sock):
    payload = b""
    
    while not payload.endswith(b"\n\n"): #TODO changer ca, risque faible d'erreur
        data = sock.recv(1024)
        if not data:
            return None
        payload = payload + data
    
    return payload[:-2]

# Handle connection
def handshake(sock, address):#TODO clear le code
    global clients
    
    # enc_pubkey = secure.export_key(passphrase=b"charlie")
    # send(sock, enc_pubkey)
    
    # receive client public key
    data = receive(sock)
    if not data:
        raise HandshakeError
    pubkey = security.import_key(data)
    
    # send session key
    session_key, nonce = security.generate_aes_key()
    data = security.encrypt_rsa(session_key + nonce, key=pubkey)
    send(sock, data)
    
    #receive and broadcast username
    data = receive(sock)
    if not data:
        raise HandshakeError
    username = security.decrypt_aes(key=session_key, nonce=nonce, ciphertext=data)
    
    client = Client(sock, address, username.decode('utf-8'), pubkey, session_key, nonce)
    clients[address] = client
    broadcast(None, f"{client.username} joined the chat")
    
    return client

# start server and client threads
def server():
    global server_socket
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(4) # handle blocked SIGINT on Win
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    log.info(f"Listenning on {HOST}:{PORT}.")

    while True:
        try:
            conn, address = server_socket.accept()
            thread = threading.Thread(target=client_thread, args=(conn, address), daemon = True)
            thread.start()
            log.info(f"New client {address}.")
        except socket.timeout:
            log.debug(f"Timeout.")
            pass

def sigint_handler(sig, frame):
    log.info("SIGINT received, closing the socket and exiting.")
    global server_socket
    if server_socket:
        server_socket.close()
    for _, client in clients.items():
        client.sock.close()
    sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)

if __name__ == "__main__":
    server()#TODO passer en classe