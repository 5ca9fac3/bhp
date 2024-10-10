import socket
import argparse

parser = argparse.ArgumentParser(description='TCP client to connect to a specified host and port')
parser.add_argument('-t', '--host', type=str, required=True, help='Target host IP address or domain')
parser.add_argument('-p', '--port', type=int, required=True, help='Target port to connect to')
args = parser.parse_args()

target_host = args.host
target_port = args.port

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((target_host, target_port))
    client_socket.send(str.encode(
        f'GET / HTTP/1.1\r\nHost: {target_host}\r\n\r\nABCDEFGH'))
    response = client_socket.recv(4096)
    print(response.decode())
except socket.error as e:
    print(f"Socket error: {e}")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    client_socket.close()
