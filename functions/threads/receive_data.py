import json

import os

import subprocess

import socket

import time

import random

import threading

import sys
sys.path.append('.')

from functions.utils.rssi_to_distance import rssi_to_distance
from functions.utils.write_probe_to_csv import write_probe_to_csv
from objects.proberequest import ProbeRequest

        

def receive_data(sock, all_received_probes):
    print(f"[receive_data]\tExecuting receive_data thread")
    while True:
        data, addr = sock.recvfrom(1024)
        #print(f"[receive_data]\treceived data")
        data_str = data.decode()

        # Parse JSON data and create ProbeRequest objects
        try:
            decoded_data = json.loads(data_str)
            probe = ProbeRequest(
                decoded_data.get("macaddress"),
                decoded_data.get("distance"),
                decoded_data.get("fingerprint"),
                decoded_data.get("sequencenumber"),
                decoded_data.get("sniffercords"),
                decoded_data.get("sniffer_ip")
            )
            all_received_probes.append(probe)
        except json.JSONDecodeError as e:
            print("Error decoding JSON:", e)
            continue
        
        print(f"[receive_probes]\tReceived This Probe)", end=" ")
        print(f"Mac: {probe.macaddress} SN: {probe.sequencenumber}")
        print(f"Length of all_received_probes = {len(all_received_probes)}")
        write_probe_to_csv("all_received_probes.csv", probe)
           
        # print("All Probe Requests Received:", all_received_probes)  # Print all received ProbeRequest objects
