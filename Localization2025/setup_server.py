import socket

Buffer = 1024

host = '192.168.1.1'  # Central device's IP address
port = 12345  # Port to listen to

# Create the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((host, port))

print("Server listening on", host, port)

while True:
    data, addr = server_socket.recvfrom(Buffer)  # Buffer size 1024
    print(f"Received message: {data} from {addr}")
    # Handle the data (e.g., save, process, etc.)
