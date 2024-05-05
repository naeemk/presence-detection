import json
import socket
import time

from objects.proberequest import ProbeRequest


# IP address and port to listen on
def create_udp_socket(interface_ip, listen_port):
    """
    Create and bind a UDP socket to the specified IP address and port.
    
    Args:
        interface_ip (str): The IP address of the network interface to bind the socket to.
        listen_port (int): The port to listen on.
    
    Returns:
        socket.socket: The created UDP socket.
    """
    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to the interface IP address and port
    udp_socket.bind((interface_ip, listen_port))
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # fixes permission error on broadcast part
    return udp_socket




# this function takes the list returned by "process_burst", encodes the data into json -> bytes and broadcasts it
def broadcast_probes(probelist, udp_socket):
    counter = 0
    broadcast_ip = "255.255.255.255"  
    broadcast_port = 12345      
    while True:
        if len(probelist) >= 1:
            while counter < len(probelist):
                probe_request_json = json.dumps({
                    "macaddress": probelist[counter].macaddress,
                    "rssi": probelist[counter].rssi,
                    "fingerprint": probelist[counter].fingerprint,
                    "sequencenumber": probelist[counter].sequencenumber,
                    "sniffercords": probelist[counter].sniffercords
                })
                probe_request_bytes = probe_request_json.encode()
                udp_socket.sendto(probe_request_bytes, (broadcast_ip, broadcast_port))
                counter+=1
        time.sleep(0.1)


# this function receives data in the form of bytes, as broadcasted above, and converts it 
# into proberequest objects then populates a list with the objects, which will be processed by trilateration function
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
                    item.get("sequencenumber"),
                    item.get("sniffercords")
                )
                all_received_probes.append(probe)
        except json.JSONDecodeError as e:
            print("Error decoding JSON:", e)
            continue
        
        print(f"[receive_probes] Received Probe Requests:")
        for probe in all_received_probes:
            print(f"  MAC Address: {probe.macaddress}, RSSI: {probe.rssi}, Fingerprint: {probe.fingerprint}, Sequence Number: {probe.sequencenumber}")
        # print("All Probe Requests Received:", all_received_probes)  # Print all received ProbeRequest objects







            
