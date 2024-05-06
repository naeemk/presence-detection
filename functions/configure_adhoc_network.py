import os
import subprocess


def configure_adhoc_network():

    def get_unique_ip(base):

        # Get the MAC address of wlan0 to generate a unique IP

        result = subprocess.run(['cat', '/sys/class/net/wlan0/address'], stdout=subprocess.PIPE)

        mac = result.stdout.decode('utf-8').strip()

        unique_suffix = int(mac.split(':')[-1], 16) % 254 + 1  # Using last byte of MAC address for uniqueness

        return f"{base}{unique_suffix}"

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
