import socket
import threading
import argparse

parser = argparse.ArgumentParser(description='TCP server to listen on a specified IP and port')
parser.add_argument('-i', '--ip', type=str, default='0.0.0.0', help='IP address to listen on;\tdefault-ip=0.0.0.0')
parser.add_argument('-p', '--port', type=int, required=True, help='Port to listen on')
args = parser.parse_args()

IP = args.ip
PORT = args.port
class TCPServer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.ip, self.port))
        self.server.listen(5)
        print(f"[*] Listening on {self.ip}:{self.port}")

    def start(self):
        while True:
            client, addr = self.server.accept()
            print(f"[*] Accepted new connection from {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(target=self.handle_client, args=(client,))
            client_handler.start()

    def handle_client(self, client_socket):
        with client_socket as sock:
            request = sock.recv(1024)
            print(f"[*] Received: {request.decode('utf-8')}")
            sock.send(b"ACK")

def main():
    server = TCPServer(IP, PORT)
    server.start()

if __name__ == '__main__':
    main()