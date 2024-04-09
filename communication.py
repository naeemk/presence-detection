import socket
import time

"""
# IP address and port to listen on
listen_ip = "0.0.0.0"  # Listen on all available network interfaces
listen_port = 12345

# Create a UDP socket
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the IP address and port
udp_socket.bind((listen_ip, listen_port))
udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # fixes permission error on broadcast part
"""






# Function to receive numbers from other Raspberry Pis, add them to own number, and print the result
def receive_probes(all_received_probes ,udp_socket):
    while True:
        data, addr = udp_socket.recvfrom(1024)  # Receive data from other Raspberry Pis
        
        # Convert bytes to string
        data_str = data.decode()

        # Parse JSON data and create ProbeRequest objects
        try:
            decoded_data = json.loads(data_str)
            for item in decoded_data:
                probe = ProbeRequest(
                    item.get("macaddress"),
                    item.get("rssi"),
                    item.get("fingerprint"),
                    item.get("sequencenumber")
                )
                all_received_probes.append(probe)
        except json.JSONDecodeError as e:
            print("Error decoding JSON:", e)
            continue
        
        print("Received Probe Requests:")
        for probe in all_received_probes:
            print(f"  MAC Address: {probe.macaddress}, RSSI: {probe.rssi}, Fingerprint: {probe.fingerprint}, Sequence Number: {probe.sequencenumber}")
        print("All Probe Requests Received:", all_received_probes)  # Print all received ProbeRequest objects






def broadcast_probes(probelist):
    i = 0
    broadcast_ip = "255.255.255.255"  
    broadcast_port = 12345      
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
            
