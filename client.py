import socket
import threading
import time
import signal
import sys

SERVER = "127.0.0.1"
PORT = 4321
USERNAME = None

def start_send(sock):
    try:
        while True:
            print(f">{USERNAME}< ", end='')
            message = input()
            if message == None or len(message) < 1 :
                pass
            else:
                sock.send(message.encode("utf-8"))
    except Exception as e:
        print(e)


def start_receive(sock):
    try:
        while True:
            message = sock.recv(1024).decode("utf-8")
            print(f"{message}")
    except Exception as e:
        print(e)
        

def sigint_handler(sig, frame):
    print('Program closed with ctrl+c')
    sock.close()
    sys.exit(0)


if __name__ =="__main__":
    
    signal.signal(signal.SIGINT, sigint_handler)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER, PORT))
    print(f"Connected to server {SERVER} : {PORT}")
    
    print("enter your username : ", end='')
    USERNAME = input()
    sock.send(USERNAME.encode("utf-8"))
    
    thread_send = threading.Thread(target=start_send, args = (sock,))
    thread_send.start()
    
    thread_rcv = threading.Thread(target=start_receive, args = (sock,))
    thread_rcv.start()
    
    while True:
        time.sleep(1000)