import socket
import time

# IP address and port to listen on
listen_ip = "0.0.0.0"  # Listen on all available network interfaces
listen_port = 12345

# Create a UDP socket
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the IP address and port
udp_socket.bind((listen_ip, listen_port))
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # fixes permission error on broadcast part



# Generate a random number

all_received_numbers = []

# Function to receive numbers from other Raspberry Pis, add them to own number, and print the result
def receive_numbers():
    while True:
        data, addr = udp_socket.recvfrom(1024)  # Receive data from other Raspberry Pis
        received_number = int(data.decode())     # Decode the received number
        if addr[0] != socket.gethostbyname(socket.gethostname()):
            all_received_numbers.append(received_number)  # Add received number to own number
            print("Result:", all_received_numbers)       # Print the result

# Start receiving numbers from other Raspberry Pis in a separate thread
import threading
threading.Thread(target=receive_numbers).start()

# Send the random number to other Raspberry Pis on the network
broadcast_ip = "255.255.255.255"  # Broadcast IP address to send to all devices on the network
broadcast_port = 12345             # Same port as the one we're listening on

# Send the random number to other Raspberry Pis every second

def broadcast(probelist):
    i = 0
    while True:
        if len(probelist) >= 1:
            while i < len(probelist):
                probe_request_json = json.dumps({
                    "macaddress": probelist[i].macaddress,
                    "rssi": probelist[i].rssi,
                    "fingerprint": probelist[i].fingerprint,
                    "sequencenumber": probelist[i].sequencenumber
                })
                probe_request_bytes = probe_request_json.encode()
                udp_socket.sendto(probe_request_bytes, (broadcast_ip, broadcast_port))
                i+=1
            time.sleep(1)
            
