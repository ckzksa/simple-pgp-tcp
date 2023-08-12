import socket
import threading
import signal
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S")

file_handler = logging.FileHandler("client.log", mode='w')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
log.addHandler(file_handler)

SERVER = "127.0.0.1"
PORT = 4321

client_socket = None
username = ""

def client_send(client_socket):
    try:
        while True:
            message = ""
            while not message:
                print(f"<{username}> ", end='')
                message = input()
                
            if message == None or len(message) < 1 :
                pass
            else:
                client_socket.send(message.encode("utf-8"))
    except EOFError:
        pass
    except Exception as e:
        log.error(e)


def client_receive(client_socket):
    try:
        while True:
            message = client_socket.recv(1024).decode("utf-8")
            print(f"{message}")
    except ConnectionResetError:
        print("Connection reset by host.")
        log.info(f"Connection reset by host.")
    except ConnectionAbortedError:
        log.info(f"Connection aborted.")
    except Exception as e:
        log.error(e)
        

def client():
    global username
    global client_socket
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER, PORT))
    
    log.debug(f"Connected to server {SERVER} : {PORT}.")
    print(f"Connected to server {SERVER} : {PORT}.")
    
    while not username:
        print("Name: ", end='')
        username = input()
    client_socket.send(username.encode("utf-8"))
    
    send_thread = threading.Thread(target=client_send, args = (client_socket,), daemon = True)
    receive_thread = threading.Thread(target=client_receive, args = (client_socket,), daemon = True)
    send_thread.start()
    receive_thread.start()
    
    send_thread.join()
    receive_thread.join()

def sigint_handler(sig, frame):
    log.info("SIGINT received, closing the socket and exiting.")
    global client_socket
    client_socket.close()
signal.signal(signal.SIGINT, sigint_handler)
    
if __name__ =="__main__":
    client()