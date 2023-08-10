import socket
import threading

SERVER = "192.168.1.9"
PORT = 4321

def start_send(sock):
    try:
        while True:
            message = input()
            if message == None or len(message) < 1 :
                pass
            else:
                sock.send(message.encode("utf-8"))
    except Exception as e:
        print(e)
        sock.close()


def start_receive(sock):
    try:
        while True:
            message = sock.recv(1024).decode("utf-8")
            print(f"{message}")
    except Exception as e:
        print(e)
        sock.close()


if __name__ =="__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER, PORT))
    print(f"Connected to server {SERVER} : {PORT}")
    
    thread_send = threading.Thread(target=start_send, args = (sock,))
    thread_send.start()
    
    thread_rcv = threading.Thread(target=start_receive, args = (sock,))
    thread_rcv.start()
