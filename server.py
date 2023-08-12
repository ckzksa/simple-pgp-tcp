import threading
import socket
import sys
import signal
import logging

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

server_socket = None
clients = {}

# broadcast a message to every clients except sender
def broadcast(sender_address, sender_username, message):
    for address, (conn, username) in clients.items():
        # don't send message to sender
        if sender_address == address:
            continue
        
        try:
            conn.send(f"<{sender_username}> {message}".encode('utf-8'))
        except Exception as e:
            log.error(f"Error sending message to {username} {address}.")

# Handle login
def login(conn, address):
    username = conn.recv(1024).decode('utf-8')
    clients[address] = (conn, username)
    broadcast(None, "SERVER", f"{username} joined the chat")
    
    return username

# Handle the client connection
def client_thread(conn, address):
    username = login(conn, address)
    
    # communicate
    try:
        while True:
            message = conn.recv(1024).decode('utf-8')
            if not message:
                break
            log.debug(f"New message from {username}: {message}.")
            broadcast(address, username, message)
    except ConnectionResetError:
        log.info(f"Connection reset {address}.")
    except ConnectionAbortedError:
        pass
    except Exception as e:
        log.error(e)
    finally:
        conn.close()
        del clients[address]
        log.info(f"Socket closed {address}.")
        broadcast(None, "SERVER", f"{username} left the chat")
        

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
    server_socket.close()
    for _, (conn, _) in clients.items():
        conn.close()
    sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)

if __name__ == "__main__":
    server()