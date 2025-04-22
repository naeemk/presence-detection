import asyncio
import json
import os
import time
import copy

import keyboard
import matplotlib.pyplot as plt

from anomaly_detection import detect_anomalies
from capture import start_sniffing, probe_data
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
        if not probe_data:
            print("[*] No probe data captured. Skipping this iteration.")
            await asyncio.sleep(1)
            continue

        # Step 2: Feature extraction
        print("[*] Extracting features from captured probe requests...")

        X, df = extract_features(probe_data)

        # Step 3: Anomaly detection
        print("[*] Detecting anomalies in the captured data...")
        detect_anomalies(X, df)

        # Sort probe_data by Timestamp
        sorted_probe_data = sorted(
            [copy.deepcopy(probe) for probe in probe_data],
            key=lambda x: x.get('Timestamp', 0)
            ) 

        # Convert Timestamps to a readable format
        for probe in sorted_probe_data:
            if 'Timestamp' in probe:
                probe['Timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(probe['Timestamp']))

        with open("data/sorted_probe_data.json", "w") as json_file:
            json.dump(sorted_probe_data, json_file, indent=4)


        #print("[*] Radar visualization updated")
        devices = fingerprint(probe_data)

        visualize_plot(devices)
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
    time.sleep(5)
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
