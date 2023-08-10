import threading
import socket
import time

HOST = "0.0.0.0"
PORT = 4321

clients = {}

def thread_client(conn, address):
    while True:
        try:
            message = conn.recv(1024).decode('utf-8')
            print(message)
            time.sleep(3)
            conn.send("server a recu")
        except:
            conn.close()
            del clients[address]
            break

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Listen on {HOST}:{PORT}")
    except Exception as e:
        print(e)

    while True:
        conn, address = s.accept()
        
        print(f"New client {address}")
        clients[address] = conn
        
        thread = threading.Thread(target=thread_client, args=(conn, address))
        thread.start()

if __name__ == "__main__":
    start_server()