import socket

server_address = ('192.168.1.1', 12345)  # Central device's address
message = b"Health status data"

# Create the client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.sendto(message, server_address)
client_socket.close()
