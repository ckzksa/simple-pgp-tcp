def send(sock, message):
    sock.sendall(message.encode("utf-8") + b"\n\n")

def receive(sock):
    message = b""
    
    while not message.endswith(b"\n\n"):
        packet = sock.recv(1024)
        message = message + packet
    
    return message.decode("utf-8")[:-2]
