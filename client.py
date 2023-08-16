import socket
import threading
import signal
import logging
import rich

from rich.prompt import Prompt
from security import Security

#TODO utiliser selects

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S")

file_handler = logging.FileHandler("client.log", mode='w')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
log.addHandler(file_handler)

SERVER = "127.0.0.1"
PORT = 4321

secure = Security(save_keys=False)
client_socket = None
session_key = None
nonce = None
username = ""

def client_send(client_socket):
    try:
        while True:
            payload = ""
            while not payload:
                rich.print(f"<[bold violet]{username}[/bold violet]> ", end='')
                payload = input()
                
            if not payload:
                pass
            else:
                payload, _ = secure.encrypt_aes(session_key, nonce, payload.encode("utf-8"))
                send(client_socket, payload)
                
    except EOFError:
        pass
    except Exception as e:
        log.error(e)


def client_receive(client_socket):
    try:
        while True:
            payload = receive(client_socket)
            payload = secure.decrypt_aes(key=session_key, nonce=nonce, ciphertext=payload)
            print(f"{payload.decode('utf-8')}")
    except ConnectionResetError:
        print("Connection reset by host.")
        log.info(f"Connection reset by host.")
    except ConnectionAbortedError:
        log.info(f"Connection aborted.")
    except Exception as e:
        log.error(e)

def send(sock, payload):
    sock.sendall(payload + b"\n\n")

def receive(sock):
    payload = b""
    
    while not payload.endswith(b"\n\n"):
        data = sock.recv(1024)
        if not data:
            return None
        payload = payload + data
    
    return payload[:-2]

# Handle connection
def handshake(sock):#TODO clear le code
    global session_key
    global nonce
    
    # receive server public key
    # data = receive(sock)
    # server_pubkey = secure.import_key(data, passphrase=b"charlie")
    
    # send public key
    pubkey = secure.export_key()
    send(sock, pubkey)
    
    # receive session key
    data = receive(sock)
    data = secure.decrypt_rsa(data, key=secure.private_key)
    session_key = data[:16]
    nonce = data[16:]
    
    # send username
    data, _ = secure.encrypt_aes(key=session_key, nonce=nonce, payload=username.encode("utf-8"))
    send(sock, data)
    
    return client

def client():
    global username
    global client_socket
    
    while not username:
        username = Prompt.ask("[bold green]Username[/bold green]")
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER, PORT))
    
    handshake(client_socket)
    
    log.debug(f"Connected to server {SERVER} : {PORT}.")
    print(f"Connected to server {SERVER} : {PORT}.")
    
    send_thread = threading.Thread(target=client_send, args = (client_socket,), daemon = True)
    receive_thread = threading.Thread(target=client_receive, args = (client_socket,), daemon = True)
    send_thread.start()
    receive_thread.start()
    
    send_thread.join()
    receive_thread.join()

def sigint_handler(sig, frame):
    log.info("SIGINT received, closing the socket and exiting.")
    global client_socket
    if client_socket:
        client_socket.close()
signal.signal(signal.SIGINT, sigint_handler)
    
if __name__ =="__main__":
    client()#TODO passer en classe