import json
import socket
import time
import threading

from objects.proberequest import ProbeRequest


# IP address and port to listen on
import socket
import random
import time

def create_udp_socket(interface_ip, listen_port):
    """
    Create and bind a UDP socket to the specified IP address and port.
    
    Args:
        interface_ip (str): The IP address of the network interface to bind the socket to.
        listen_port (int): The port to listen on.
    
    Returns:
        socket.socket: The created UDP socket.
    """
    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the interface IP address and port
    udp_socket.bind((interface_ip, listen_port))
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # enable broadcast
    return udp_socket

def broadcast_random_numbers(udp_socket, broadcast_port):
    """
    Broadcast random numbers over the UDP socket.
    
    Args:
        udp_socket (socket.socket): The UDP socket to use for broadcasting.
        broadcast_port (int): The port to broadcast to.
    """
    while True:
        # Generate a random number
        random_number = random.randint(1, 100)
        
        # Convert the random number to bytes
        message = str(random_number).encode()
        
        # Broadcast the message
        udp_socket.sendto(message, ('<broadcast>', broadcast_port))
        
        print(f"Broadcasted: {random_number}")
        
        # Wait for a short interval before broadcasting again
        time.sleep(1)

def receive_numbers(udp_socket):
    """
    Receive numbers from the UDP socket and print them to the console.
    
    Args:
        udp_socket (socket.socket): The UDP socket to use for receiving.
    """
    while True:
        # Receive data from the socket
        data, addr = udp_socket.recvfrom(1024)
        
        # Decode the received data
        received_number = int(data.decode())
        
        print(f"Received: {received_number} from {addr[0]}")

# Set the interface IP address and port
interface_ip = '192.168.1.1'  # Example IP address for the interface
listen_port = 12345  # Port to listen on
broadcast_port = 12345  # Port to broadcast to

# Create a UDP socket
udp_socket = create_udp_socket(interface_ip, listen_port)

# Start the broadcasting thread
broadcast_thread = threading.Thread(target=broadcast_random_numbers, args=(udp_socket, broadcast_port))
broadcast_thread.start()

# Start the receiving thread
receive_thread = threading.Thread(target=receive_numbers, args=(udp_socket,))
receive_thread.start()
