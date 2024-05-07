import json

import os

import subprocess

import socket

import time

import random

import threading

from functions.utils.rssi_to_distance import rssi_to_distance
from objects.proberequest import ProbeRequest

 
 


 

def send_data(sock, network_ips, probelist):
    print(f"[send_data]\tExecuting send_data thread")
    counter = 0  
    while True:
        print(f"[send_data]\tchecking if probelist: {len(probelist)} >= 1")
        if len(probelist) >= 1:
            print(f"[send_data]\tchecking if counter: {counter} < probelist: {len(probelist)}")
            while counter < len(probelist):
                probe_request_json = json.dumps({
                    "macaddress": probelist[counter].macaddress,
                    "distance": probelist[counter].distance,
                    "fingerprint": probelist[counter].fingerprint,
                    "sequencenumber": probelist[counter].sequencenumber,
                    "sniffercords": probelist[counter].sniffercords
                })
                probe_request_bytes = probe_request_json.encode()
                for ip in network_ips:
                    sock.sendto(probe_request_bytes, (ip, 12345))
                counter+=1
                print(f"[send_data]\tSent this probe request {probelist[counter].macaddress}")
        time.sleep(0.1)

 

def receive_data(sock, all_received_probes):
    print(f"[receive_data]\tExecuting receive_data thread")
    while True:

        data, addr = sock.recvfrom(1024)
        print(f"[receive_data]\treceived data")
        data_str = data.decode()

        # Parse JSON data and create ProbeRequest objects
        try:
            decoded_data = json.loads(data_str)
            for item in decoded_data:
                probe = ProbeRequest(
                    item.get("macaddress"),
                    item.get("distance"),
                    item.get("fingerprint"),
                    item.get("sequencenumber"),
                    item.get("sniffercords")
                )
                all_received_probes.append(probe)
        except json.JSONDecodeError as e:
            print("Error decoding JSON:", e)
            continue
        
        print(f"[receive_probes] Received This Probe)")
        print(f"\n \tMac: {probe.macaddress}\tSN: {probe.sequencenumber}\tSniffercords: {probe.sniffercords}")
           
        # print("All Probe Requests Received:", all_received_probes)  # Print all received ProbeRequest objects
