import subprocess

def get_ip_address(interface):
    result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
    output = result.stdout
    # Extracting the IP address using regular expression
    ip_address = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', output)
    if ip_address:
        return ip_address.group(1)
    else:
        return None

