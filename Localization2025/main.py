import asyncio
import json
import os
import time

import keyboard
import matplotlib.pyplot as plt

from anomaly_detection import detect_anomalies
from capture import start_sniffing, probe_data
from clustering import cluster_data
from device_signature import get_device_name
from feature_extraction import extract_features
#from radar import visualize_radar  # Import radar visualization function
from plot import visualize_plot
from fingerprinting.fingerprinting import fingerprint

def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)
config = load_config()

interface = config["general"]["interface"]
datafile1 = config["jsonfiles"]["probe_request_results"]
datafile2 = config["jsonfiles"]["probe_request_results_clustered"]

# List to store all clustered results
clustered_results_all = []

def on_click(event):
    print(f"Clicked at ({event.x}, {event.y})")


async def save_packets():
    while True:
        # Step 2: Feature extraction
        print("[*] Extracting features from captured probe requests...")

        if not probe_data:
            print("[*] No probe data captured. Skipping this iteration.")
            await asyncio.sleep(1)
            continue

        X, df = extract_features(probe_data)

        # Step 3: Anomaly detection
        print("[*] Detecting anomalies in the captured data...")
        detect_anomalies(X, df)

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
        
        fingerprint(probe_data)
        await asyncio.sleep(1)

async def main():
    # Check if the file exists
    if os.path.exists(datafile1 + ".json"):
        # Rename the existing file to .bak
        os.rename(datafile1 + ".json", datafile1 + ".json.bak")
        print("[*] Existing '" + datafile1 +".json' renamed to '" + datafile1 +".json.bak'")

    if os.path.exists(datafile2 + ".json"):
        # Rename the existing file to .bak
        os.rename(datafile2 + ".json", datafile2 + ".json.bak")
        print("[*] Existing '" + datafile2 +".json' renamed to '" + datafile2 +".json.bak'")

    plt.ion()
    plt.draw()
    plt.show()


    # Step 1: Start sniffing and capture probe requests until you press 'esc'
    task1 = asyncio.create_task(start_sniffing(interface))  # Replace with your Wi-Fi interface
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
