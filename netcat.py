import argparse
import shlex
import socket
import subprocess
import sys
import textwrap
import threading

# This function will execute the provided shell command


def execute(cmd):
    cmd = cmd.strip()  # Remove any leading or trailing whitespace
    if not cmd:
        return
    try:
        # Execute the command and return the output
        output = subprocess.check_output(
            shlex.split(cmd), stderr=subprocess.STDOUT)
        return output.decode()  # Decode the output to string
    except subprocess.CalledProcessError as e:
        # Return error message if command fails
        return f"Failed to execute command: {e}"

# Netcat class that has functions to handle the different modes of operation


class Netcat:
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        # Create a socket object using IPv4 and TCP
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set socket option to reuse address, helps in restarting the server quickly
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Run method to decide whether to listen or send based on arguments
    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def send(self):
        try:
            # Connect to the target IP and port
            self.socket.connect((self.args.target, self.args.port))
            if self.buffer:
                # Send the initial buffer if present
                self.socket.send(self.buffer)
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    # Receive data from the target
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()  # Append the received data to the response
                    if recv_len < 4096:
                        break  # If received data is less than 4096 bytes, break the loop
                if response:
                    print(response)  # Print the response
                    buffer = input('> ')  # Get user input
                    buffer += '\n'  # Add newline character to the input
                    # Send the input back to the target
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            print('User Terminated.')
        except socket.error as e:
            print(f"Socket error: {e}")
        finally:
            self.socket.close()

    def listen(self):
        # Bind to the target IP and port and start listening
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)  # Set maximum number of queued connections
        try:
            while True:
                # Accept a new client connection
                client_socket, _ = self.socket.accept()
                # Create a new thread to handle the client
                client_thread = threading.Thread(
                    target=self.handle, args=(client_socket,))
                client_thread.start()  # Start the client thread
        except KeyboardInterrupt:
            print('Listener terminated.')
        except socket.error as e:
            print(f"Socket error: {e}")
        finally:
            self.socket.close()

    def handle(self, client_socket):
        with client_socket as sock:
            try:
                if self.args.execute:
                    output = execute(self.args.execute)  # Execute the command
                    # Send the output back to the client
                    sock.send(output.encode())

                elif self.args.upload:
                    file_buffer = b''
                    while True:
                        data = sock.recv(4096)  # Receive data from the client
                        if data:
                            file_buffer += data  # Append data to file buffer
                        else:
                            break  # Break when no more data is received

                    # Write the received data to the specified file
                    with open(self.args.upload, 'wb') as f:
                        f.write(file_buffer)
                    message = f'Saved file {self.args.upload}'
                    # Send confirmation message to client
                    sock.send(message.encode())

                elif self.args.command:
                    cmd_buffer = b''
                    while True:
                        try:
                            sock.send(b'BHP #> ')  # Send prompt to the client
                            while '\n' not in cmd_buffer.decode():
                                # Receive command input
                                cmd_buffer += sock.recv(64)
                            # Execute command
                            response = execute(cmd_buffer.decode())
                            if response:
                                # Send the output back to client
                                sock.send(response.encode())
                                cmd_buffer = b''  # Reset the command buffer
                        except Exception as e:
                            print(f'Server killed {e}')
                            break
            except socket.error as e:
                print(f"Socket error: {e}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="BHP Net tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
        netcat.py -t 192.168.1.108 -p 5555 -l -c # command shell
        netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.txt # upload to file
        netcat.py -t 192.168.1.108 -p 5555 -l -e="cat /etc/passwd" # execute command
        echo 'ABC' | ./netcat.py -t 192.168.1.108 -p 135 # echo text to server port 135
        netcat.py -t 192.168.1.108 -p 5555 # connect to server
        '''))
    parser.add_argument('-c', '--command',
                        action='store_true', help='command shell')  # Flag to indicate command shell
    # Command to execute
    parser.add_argument('-e', '--execute', help='execute specified command')
    # Flag to indicate listening mode
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int,
                        default=5555, help='specified port')  # Port to connect or bind to
    parser.add_argument(
        '-t', '--target', default='192.168.1.203', help='specified IP')  # Target IP address
    parser.add_argument('-u', '--upload', help='upload file')  # File to upload
    args = parser.parse_args()
    if args.listen:
        buffer = ''  # Empty buffer if listening
    else:
        buffer = sys.stdin.read()  # Read input from stdin if sending

    nc = Netcat(args, buffer.encode())
    nc.run()
