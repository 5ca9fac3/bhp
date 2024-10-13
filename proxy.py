import sys  # Import system-specific parameters and functions
import socket  # Import socket module for network communication
import threading  # Import threading module to handle multiple connections
import argparse  # Import argparse to parse command-line arguments

# Create a filter to display printable characters, replacing non-printable with '.'
HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

# Function to print a hex dump of the data
# Displays data in both hexadecimal and ASCII format
def hexdump(src, length=16, show=True):
    if isinstance(src, bytes):
        src = src.decode(errors='replace')  # Decode bytes to string, replacing errors

    results = list()  # Initialize results list to store formatted strings
    for i in range(0, len(src), length):
        word = str(src[i:i+length])  # Extract a chunk of data
        printable = word.translate(HEX_FILTER)  # Filter out non-printable characters
        hexa = ' '.join([f'{ord(c):02X}' for c in word])  # Convert each character to its hex value
        hexwidth = length * 3  # Calculate width for hex representation
        results.append(f'{i:04X} {hexa:<{hexwidth}} {printable}')  # Format and append to results

    if show:
        for line in results:
            print(line)  # Print each line if show is True
    else:
        return results  # Return the results if show is False

# Function to receive data from a socket connection
def receive_from(connection):
    buffer = b''  # Initialize an empty buffer
    connection.settimeout(5)  # Set a timeout of 5 seconds for the connection
    try:
        while True:
            data = connection.recv(4096)  # Receive up to 4096 bytes of data
            if not data:
                break  # Break the loop if no more data is received
            buffer += data  # Append the received data to the buffer
    except socket.timeout:
        pass  # Ignore timeout exceptions
    except Exception as e:
        print(f"Error receiving data: {e}")  # Print any other errors that occur
    return buffer  # Return the collected buffer

# Function to handle modifications to the request packets before sending them
def request_handler(buffer):
    # Perform packet modifications
    return buffer  # Return the modified buffer (currently no modification is done)

# Function to handle modifications to the response packets before sending them
def response_handler(buffer):
    # Perform packet modifications
    return buffer  # Return the modified buffer (currently no modification is done)

# Function to handle the proxy between local and remote connections
def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    # Create a remote socket to connect to the target
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))  # Connect to the remote host

    # If receive_first flag is set, receive data from the remote host first
    if receive_first:
        remote_buffer = receive_from(remote_socket)  # Receive data from the remote host
        hexdump(remote_buffer)  # Print the hex dump of the received data
        remote_buffer = response_handler(remote_buffer)  # Modify the response if needed
        if len(remote_buffer):
            client_socket.send(remote_buffer)  # Send the modified response to the client

    # Loop to continually receive and forward data between client and remote server
    while True:
        local_buffer = receive_from(client_socket)  # Receive data from the client
        if len(local_buffer):
            hexdump(local_buffer)  # Print the hex dump of the received data
            local_buffer = request_handler(local_buffer)  # Modify the request if needed
            remote_socket.send(local_buffer)  # Send the modified request to the remote server

        remote_buffer = receive_from(remote_socket)  # Receive data from the remote server
        if len(remote_buffer):
            hexdump(remote_buffer)  # Print the hex dump of the received data
            remote_buffer = response_handler(remote_buffer)  # Modify the response if needed
            client_socket.send(remote_buffer)  # Send the modified response to the client

        # If no more data is received from either side, close the sockets
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()  # Close the client socket
            remote_socket.close()  # Close the remote socket
            break  # Break the loop to stop the proxy

# Function to set up a server loop to listen for incoming connections
def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a server socket
    server.bind((local_host, local_port))  # Bind to the specified local IP and port
    server.listen(5)  # Listen for incoming connections, with a backlog of 5

    print(f"[*] Listening on {local_host}:{local_port}")  # Print listening status

    while True:
        client_socket, addr = server.accept()  # Accept an incoming connection
        print(f"[*] Received incoming connection from {addr[0]}:{addr[1]}")  # Print client info
        # Start a new thread to handle the proxy connection
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()  # Start the proxy thread

# Main entry point for the script
if __name__ == '__main__':
    # Set up argument parsing for command-line inputs
    parser = argparse.ArgumentParser(description="TCP Proxy Tool")
    parser.add_argument("-lh", "--localhost", required=True, help="Local host to bind to")  # Local IP to bind to
    parser.add_argument("-lp", "--localport", type=int, required=True, help="Local port to bind to")  # Local port to bind to
    parser.add_argument("-rh", "--remotehost", required=True, help="Remote host to connect to")  # Remote target IP
    parser.add_argument("-rp", "--remoteport", type=int, required=True, help="Remote port to connect to")  # Remote target port
    parser.add_argument("-rf", "--receivefirst", action="store_true", help="Receive data from the remote host first")  # Flag for receiving data first
    args = parser.parse_args()  # Parse the arguments

    # Call server loop with the provided arguments
    server_loop(args.localhost, args.localport, args.remotehost, args.remoteport, args.receivefirst)
