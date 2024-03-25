import socket
import random

# IP address and port to listen on
listen_ip = "0.0.0.0"  # Listen on all available network interfaces
listen_port = 12345

# Create a UDP socket
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the IP address and port
udp_socket.bind((listen_ip, listen_port))

# Generate a random number
random_number = random.randint(1, 100)

# Function to receive numbers from other Raspberry Pis, add them to own number, and print the result
def receive_numbers():
    while True:
        data, addr = udp_socket.recvfrom(1024)  # Receive data from other Raspberry Pis
        received_number = int(data.decode())     # Decode the received number
        random_number += received_number         # Add received number to own number
        print("Result:", random_number)          # Print the result

# Start receiving numbers from other Raspberry Pis in a separate thread
import threading
threading.Thread(target=receive_numbers).start()

# Send the random number to other Raspberry Pis on the network
broadcast_ip = "255.255.255.255"  # Broadcast IP address to send to all devices on the network
broadcast_port = 12345             # Same port as the one we're listening on

# Send the random number to other Raspberry Pis every second
import time
while True:
    udp_socket.sendto(str(random_number).encode(), (broadcast_ip, broadcast_port))
    time.sleep(1)
