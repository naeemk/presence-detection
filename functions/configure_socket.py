import socket


def configure_socket(interface_ip):

    # Bind a socket to the interface IP and a specific port for UDP communication

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind((interface_ip, 12345))

    return sock