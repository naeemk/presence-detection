import asyncio
import json
import os
import time

import keyboard
import matplotlib.pyplot as plt

from anomaly_detection import detect_anomalies
from capture import probe_data
from tempbackup.clustering import cluster_data
from tempbackup.device_signature import get_device_name
from feature_extraction import extract_features
#from radar import visualize_radar  # Import radar visualization function
from plot import visualize_plot
from scapy.all import rdpcap
from fingerprinting.fingerprinting import fingerprint
from capture import handle_probe_request

def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)
config = load_config()

interface = config["general"]["interface"]
fake_seconds = config["general"]["fake_seconds_offline"]
pcap_file = config["jsonfiles"]["pcap_file"]
datafile1 = config["jsonfiles"]["probe_request_results"]
datafile2 = config["jsonfiles"]["probe_request_results_clustered"]

# List to store all clustered results
clustered_results_all = []

def on_click(event):
    print(f"Clicked at ({event.x}, {event.y})")

async def offline_packets():
    while True:
        print(f"[*] Faking Wi-Fi probe requests with {fake_seconds} second(s) interval...")
        packets = rdpcap(pcap_file)
        print(f"[*] Loaded {len(packets)} packets from '{pcap_file}'")

        for packet in packets:
            handle_probe_request(packet)
            await asyncio.sleep(fake_seconds)

        await asyncio.sleep(2)

async def save_packets():
    while True:
        # Step 2: Feature extraction
        print("[*] Extracting features from captured probe requests...")

        if not probe_data:
            print("[*] No probe data captured. Skipping this iteration.")
            await asyncio.sleep(1)
            continue

        #X, df = extract_features(probe_data)

        # Step 3: Anomaly detection
        #print("[*] Detecting anomalies in the captured data...")
        #detect_anomalies(X, df)

        # Step 4: Assign device names based on device signatures (e.g., SSID, RSSI, Probe Interval)
        print("[*] Assigning device names...")
        
        # Structure the data into a list of dictionaries suitable for JSON
        json_data = []

        for entry in probe_data:
            # Create a device signature based on SSID and other features like RSSI, Probe Interval, etc.
            device_signature = (entry["SSID"], entry["MAC"], entry["Features"])

            # Get or assign a device name based on the device signature
            device_name = get_device_name(device_signature)

            # Add the device name to the entry
            json_entry = {
                "Device_Name": device_name,
                "MAC": entry["MAC"],
                "SSID": entry["SSID"],
                "RSSI": entry["RSSI"],
                "Timestamp": entry["Timestamp"],
                "Features": entry["Features"]
            }
            json_data.append(json_entry)

        # Step 5: Save captured data to a JSON file
        print("[*] Saving captured data to '" + datafile1 + ".json'...")
        
        with open(datafile1+".json", "w") as json_file:
            json.dump(json_data, json_file, indent=4)

        print("[*] Data saved to '" + datafile1 + ".json'")
        

        # Step 6: Cluster the data

        # Load JSON data
        #with open("probe_request_results.json", "r") as file:
        #   data = json.load(file)
        fingerprint(probe_data)
        
        # Perform clustering
        print("[*] Clustering data...")
        clustered_results = cluster_data(json_data)
        
        # Step 7: Call radar visualization function
        print("Generating radar visualization...")
        print(clustered_results)
        #visualize_radar(clustered_results, ax)
        #print("[*] Radar visualization updated")
        visualize_plot(clustered_results)
        print("[*] Plot visualization updated")
        
        await asyncio.sleep(1)

async def main():
    # Check if the file exists
    if os.path.exists(datafile1 + ".json"):
        backup_file1 = datafile1 + ".json.bak"
        if os.path.exists(backup_file1):
            os.remove(backup_file1)
        os.rename(datafile1 + ".json", backup_file1)
        print(f"[*] Existing '{datafile1}.json' renamed to '{backup_file1}'")

    if os.path.exists(datafile2 + ".json"):
        backup_file2 = datafile2 + ".json.bak"
        if os.path.exists(backup_file2):
            os.remove(backup_file2)
        os.rename(datafile2 + ".json", backup_file2)
        print(f"[*] Existing '{datafile2}.json' renamed to '{backup_file2}'")

    plt.ion()
    plt.draw()
    plt.show()

    # Step 1: Start sniffing and capture probe requests until you press 'esc'
    task1 = asyncio.create_task(offline_packets())  # Replace with your Wi-Fi interface
    time.sleep(3)
    task2 = asyncio.create_task(save_packets())
    print("[*] Capturing data...")

    while True:
        if keyboard.is_pressed('esc'):
            print("[*] Stopping the program...")
            break
        await asyncio.sleep(1)
    
    plt.ioff()
    task1.cancel()
    task2.cancel()
    try:
        await task1
    except asyncio.CancelledError:
        print("[*] Sniffing task cancelled")
    try:
        await task2
    except asyncio.CancelledError:
        print("[*] Saving task cancelled")

    print("[*] Program completed")
    
if __name__ == "__main__":
    asyncio.run(main())
