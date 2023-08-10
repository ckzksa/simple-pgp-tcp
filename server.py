import threading
import socket
import sys
import signal

HOST = "0.0.0.0"
PORT = 4321

server_socket = None
clients = {}

def broadcast(sender_address, sender_username, message):
    for address, (conn, username) in clients.items():
        if sender_address == address:
            continue
        
        try:
            conn.send(f"<{sender_username}> {message}".encode('utf-8'))
        except Exception as e:
            print(f"Error sending message to {username}")

def thread_client(conn, address):
    #get username
    username = conn.recv(1024).decode('utf-8')
    clients[address] = (conn, username)
    
    #communication
    while True:
        try:
            message = conn.recv(1024).decode('utf-8')
            broadcast(address, username, message)
        except Exception as e:
            print(e)
            conn.close()
            del clients[address]
            break

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.settimeout(4)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Listen on {HOST}:{PORT}")

    while True:
        try:
            conn, address = server_socket.accept()
            thread = threading.Thread(target=thread_client, args=(conn, address))
            thread.start()
            print(f"New client {address}")
        except TimeoutError:
            pass

if __name__ == "__main__":
    start_server()