import threading
import socket
import time
import sys

HOST = "0.0.0.0"
PORT = 4321

clients = {}

def thread_client(conn, address):
    while True:
        try:
            message = conn.recv(1024).decode('utf-8')
            print(message)
            time.sleep(3)
            conn.send("<server> recu".encode('utf-8'))
        except Exception as e:
            print(e)
            conn.close()
            del clients[address]
            break

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listen on {HOST}:{PORT}")

    while True:
        try:
            conn, address = s.accept()
            clients[address] = conn
            thread = threading.Thread(target=thread_client, args=(conn, address))
            thread.start()
            print(f"New client {address}")
        except TimeoutError:
            print("timeout")
            pass

if __name__ == "__main__":
    start_server()