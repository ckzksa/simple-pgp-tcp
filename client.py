import socket
import threading

SERVER = "127.0.0.1"
PORT = 4321
MSG_MAX_SIZE = 1024

def init_connection():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("press enter to connect to the server")
    input()
    try:
        sock.connect((SERVER, PORT))
    except Exception as e:
        print(e)
    print(f"connecting to server {SERVER} : {PORT}")
    return sock


def start_send(sock):
    talk = True
    while talk:
        message = input()
        if message == None or len(message) < 1 :
            print ("wrong message")
        else:
            try:
                sock.send(message.encode("utf-8"))
            except Exception as e:
                print(e)
                talk=False
    try:
        sock.close()
    except Exception as e:
            print(e)


def start_receive(sock):
    talk = True
    while talk:
        try:
            message = sock.recv(MSG_MAX_SIZE).decode("utf-8")
            print(f"{message}")
        except Exception as e:
            print(e)
            talk=False
    try:
        sock.close()
    except Exception as e:
            print(e)


if __name__ =="__main__":
    sock = init_connection()
    thread_send = threading.Thread(target=start_send, args = (sock))
    thread_send.start()
    
    thread_rcv = threading.Thread(target=start_receive, args = (sock))
    thread_rcv.start()
