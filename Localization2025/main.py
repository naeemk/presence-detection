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
capture_delay = config["general"]["capture_delay"]
datafile1 = config["jsonfiles"]["mac_data"]
datafile2 = config["jsonfiles"]["ssid_data"]
datafile3 = config["jsonfiles"]["feature_data"]
datafile4 = config["jsonfiles"]["devices"]
datafile5 = config["jsonfiles"]["probe_data"]

# List to store all clustered results
clustered_results_all = []

def on_click(event):
    print(f"Clicked at ({event.x}, {event.y})")


async def handle_data():
    while True:
        if not probe_data:
            print("[*] No probe data captured. Skipping this iteration.")
            await asyncio.sleep(1)
            continue

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

        devices = fingerprint(probe_data)

        visualize_plot(devices)
        print("[*] Plot visualization updated")
        
        await asyncio.sleep(1)

async def main():
    start_time = time.time()  # Start timer

    # Renaming the existing files to .bak
    for datafile in [datafile1, datafile2, datafile3, datafile4, datafile5]:
        json_file = datafile + ".json"
        backup_file = json_file + ".bak"
        if os.path.exists(json_file):
            os.rename(json_file, backup_file)
            print(f"[*] Existing '{json_file}' renamed to '{backup_file}'")

    plt.ion()
    plt.draw()
    plt.show()

    try:
        # Start sniffing and capture probe requests
        task1 = asyncio.create_task(start_sniffing(interface))
        print(f"[*] Sniffing started on {interface}, waiting {capture_delay}s before data handling.")
        
        await asyncio.sleep(capture_delay)
        # Start data handling
        task2 = asyncio.create_task(handle_data())
        print("[*] Data handler started...")

        while True:
            await asyncio.sleep(1)
            if keyboard.is_pressed('esc'):
                print("[*] ESC pressed, stopping...")
                break

    except Exception as e:
        print(f"[!] Error during execution: {e}")
    finally:
        # Clean exit: cancel tasks and close plot
        plt.ioff()

        for task in [task1, task2]:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    print(f"[*] Task {task.get_coro().__name__} cancelled")
        end_time = time.time()
        elapsed = end_time - start_time
        minutes, seconds = divmod(int(elapsed), 60)
        print(f"[*] Program completed. Total runtime: {minutes} min {seconds} sec.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Exiting cleanly.")