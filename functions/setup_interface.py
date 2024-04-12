import subprocess

def setup_interface(interface):
    global monitor_interface
    # Commands to set up the interface for monitoring
    subprocess.call(["sudo", "ifconfig", interface, "down"])
    subprocess.call(["sudo", "airmon-ng", "start", interface])
    # Adjust for your environment - some systems rename the interface to wlan0mon
    monitor_interface = "wlan0mon" if interface == "wlan0" else interface
    subprocess.call(["sudo", "ifconfig", monitor_interface, "up"])
    print(f"{monitor_interface} set to monitor mode and brought up.")
