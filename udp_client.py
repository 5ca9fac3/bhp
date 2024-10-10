import socket
import argparse

parser = argparse.ArgumentParser(description='UDP client to send data to a specified host and port')
parser.add_argument('-t', '--target', type=str, required=True, help='Target host IP address or domain')
parser.add_argument('-p', '--port', type=int, required=True, help='Target port to send data to')
args = parser.parse_args()

target_host = args.target
target_port = args.port

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    client.sendto(b"AAABBBBCCCCC", (target_host, target_port))
    data, addr = client.recvfrom(4096)
    print(data.decode())
except socket.error as e:
    print(f"Socket error: {e}")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    client.close()