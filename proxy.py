import sys  # Import system-specific parameters and functions
import socket  # Import socket module for network communication
import threading  # Import threading module to handle multiple connections
import argparse  # Import argparse to parse command-line arguments

# Create a filter to display printable characters, replacing non-printable with '.'
HEX_FILTER = "".join([(len(repr(chr(i))) == 3) and chr(i) or "." for i in range(256)])


# Function to print a hex dump of the data
# Displays data in both hexadecimal and ASCII format
def hexdump(src, length=16, show=True):
    if isinstance(src, bytes):
        # Decode bytes to string, replacing errors
        src = src.decode(errors="replace")

    results = list()  # Initialize results list to store formatted strings
    for i in range(0, len(src), length):
        word = str(src[i : i + length])  # Extract a chunk of data
        # Filter out non-printable characters
        printable = word.translate(HEX_FILTER)
        # Convert each character to its hex value
        hexa = " ".join([f"{ord(c):02X}" for c in word])
        hexwidth = length * 3  # Calculate width for hex representation
        # Format and append to results
        results.append(f"{i:04X} {hexa:<{hexwidth}} {printable}")

    if show:
        for line in results:
            print(line)  # Print each line if show is True
    else:
        return results  # Return the results if show is False


# Function to receive data from a socket connection
def receive_from(connection):
    buffer = b""  # Initialize an empty buffer
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
        # Print any other errors that occur
        print(f"Error receiving data: {e}")
    return buffer  # Return the collected buffer


# Function to handle modifications to the request packets before sending them
def request_handler(buffer):
    # Perform packet modifications
    # Return the modified buffer (currently no modification is done)
    return buffer


# Function to handle modifications to the response packets before sending them
def response_handler(buffer):
    # Perform packet modifications
    # Return the modified buffer (currently no modification is done)
    return buffer


# Function to handle the proxy between local and remote connections
def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    # Create a remote socket to connect to the target
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to the remote host
    remote_socket.connect((remote_host, remote_port))

    # If receive_first flag is set, receive data from the remote host first
    if receive_first:
        # Receive data from the remote host
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)  # Print the hex dump of the received data
        # Modify the response if needed
        remote_buffer = response_handler(remote_buffer)
        if len(remote_buffer):
            # Send the modified response to the client
            client_socket.send(remote_buffer)

    # Loop to continually receive and forward data between client and remote server
    while True:
        # Receive data from the client
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            hexdump(local_buffer)  # Print the hex dump of the received data
            # Modify the request if needed
            local_buffer = request_handler(local_buffer)
            # Send the modified request to the remote server
            remote_socket.send(local_buffer)

            # Check if the command is related to entering passive mode (e.g., PASV)
            if b"PASV" in local_buffer.upper():
                # Handle passive data connection
                passive_data_handler(client_socket, remote_socket)

        # Receive data from the remote server
        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            hexdump(remote_buffer)  # Print the hex dump of the received data
            # Modify the response if needed
            remote_buffer = response_handler(remote_buffer)
            # Send the modified response to the client
            client_socket.send(remote_buffer)

        # If no more data is received from either side, close the sockets
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()  # Close the client socket
            remote_socket.close()  # Close the remote socket
            break  # Break the loop to stop the proxy


# Function to handle passive mode FTP data connections
def passive_data_handler(client_socket, remote_socket):
    # Create a socket to handle the data connection
    data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_socket.bind(("", 0))  # Bind to an available port
    data_socket.listen(1)

    # Get the port number and send it to the remote server
    _, port = data_socket.getsockname()
    port_command = f"PORT 127,0,0,1,{port // 256},{port % 256}\r\n"
    client_socket.send(port_command.encode())

    # Accept the incoming connection from the client for data transfer
    data_client_socket, _ = data_socket.accept()

    # Loop to handle data transfer between client and remote server
    while True:
        data_from_client = receive_from(data_client_socket)
        if len(data_from_client):
            hexdump(data_from_client)
            remote_socket.send(data_from_client)

        data_from_remote = receive_from(remote_socket)
        if len(data_from_remote):
            hexdump(data_from_remote)
            data_client_socket.send(data_from_remote)

        # If no more data is received from either side, close the sockets
        if not len(data_from_client) or not len(data_from_remote):
            data_client_socket.close()
            data_socket.close()
            break


# Function to set up a server loop to listen for incoming connections
def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    # Create a server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind to the specified local IP and port
    server.bind((local_host, local_port))
    server.listen(5)  # Listen for incoming connections, with a backlog of 5

    # Print listening status
    print(f"[*] Listening on {local_host}:{local_port}")

    while True:
        client_socket, addr = server.accept()  # Accept an incoming connection
        # Print client info
        print(f"[*] Received incoming connection from {addr[0]}:{addr[1]}")
        # Start a new thread to handle the proxy connection
        proxy_thread = threading.Thread(
            target=proxy_handler,
            args=(client_socket, remote_host, remote_port, receive_first),
        )
        proxy_thread.start()  # Start the proxy thread


# Main entry point for the script
if __name__ == "__main__":
    # Set up argument parsing for command-line inputs
    parser = argparse.ArgumentParser(description="TCP Proxy Tool")
    parser.add_argument(
        "-lh", "--localhost", required=True, help="Local host to bind to"
    )  # Local IP to bind to
    parser.add_argument(
        "-lp", "--localport", type=int, required=True, help="Local port to bind to"
    )  # Local port to bind to
    parser.add_argument(
        "-rh", "--remotehost", required=True, help="Remote host to connect to"
    )  # Remote target IP
    parser.add_argument(
        "-rp", "--remoteport", type=int, required=True, help="Remote port to connect to"
    )  # Remote target port
    parser.add_argument(
        "-rf",
        "--receivefirst",
        type=int,
        required=True,
        help="Receive data from the remote host first",
    )  # Flag for receiving data first
    args = parser.parse_args()  # Parse the arguments

    # Call server loop with the provided arguments
    server_loop(
        args.localhost,
        args.localport,
        args.remotehost,
        args.remoteport,
        args.receivefirst,
    )
