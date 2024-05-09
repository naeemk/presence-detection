import os

import subprocess

import socket

import time

import random

import threading

 

def get_unique_ip(base):

    # Get the MAC address of wlan0 to generate a unique IP

    result = subprocess.run(['cat', '/sys/class/net/wlan0/address'], stdout=subprocess.PIPE)

    mac = result.stdout.decode('utf-8').strip()

    unique_suffix = int(mac.split(':')[-1], 16) % 254 + 1  # Using last byte of MAC address for uniqueness

    return f"{base}{unique_suffix}"

 

def configure_adhoc_network():

    # Stop interfering services

    os.system('sudo systemctl stop NetworkManager')

    os.system('sudo systemctl stop wpa_supplicant')

    os.system('sudo ifconfig wlan0 down')

    os.system('sudo iwconfig wlan0 mode ad-hoc')

    os.system('sudo iwconfig wlan0 essid "YourAdHocSSID"')

    os.system('sudo iwconfig wlan0 channel 1')

    # Assign unique IP based on MAC address

    unique_ip = get_unique_ip('10.192.200.')

    os.system(f'sudo ifconfig wlan0 {unique_ip} netmask 255.255.0.0')

    os.system('sudo ifconfig wlan0 up')

    return unique_ip

 

def configure_socket(interface_ip):

    # Bind a socket to the interface IP and a specific port for UDP communication

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind((interface_ip, 12345))

    return sock

 

def send_data(sock, target_ip, message):

    sock.sendto(message.encode(), (target_ip, 12345))

 

def receive_data(sock):

    while True:

        data, addr = sock.recvfrom(1024)

        print(f"These values {data.decode()} are from {addr[0]}")

 

if __name__ == "__main__":

    my_ip = configure_adhoc_network()

    sock = configure_socket(my_ip)

    network_ips = [f"10.192.200.{i}" for i in range(1, 255) if f"10.192.200.{i}" != my_ip]

 

    # Start receiving data in a separate thread

    threading.Thread(target=receive_data, args=(sock,), daemon=True).start()

 

    # Continuously send random data to other Pis on the network

    while True:

        random_value = random.randint(1000, 9999)

        for ip in network_ips:

            send_data(sock, ip, f"Random value {random_value}")

        time.sleep(5)