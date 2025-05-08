import json
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
import datetime

# Index selection variable - change this to select different data points
# If the file contains multiple measurements for the same distance at different times,
# this can be used to filter them
selected_index = 0  # Change this value to select different indices/measurements

def load_rssi_data(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []
    except json.JSONDecodeError:
        print(f"Invalid JSON format in file: {file_path}")
        return []

def create_boxplot(rssi_data, selected_index=None):
    # Group data by distance
    distance_data = defaultdict(list)
    
    # Process each entry
    for entry in rssi_data:
        distance = entry.get("distance")
        rssi_values = entry.get("rssi_values", [])
        timestamp = entry.get("timestamp")
        
        # Add data to our grouped dictionary
        if distance is not None and rssi_values:
            distance_data[distance].extend(rssi_values)
    
    # If no data was found
    if not distance_data:
        print("No valid RSSI data found in the file.")
        return None
    
    # Sort distances
    distances = sorted(distance_data.keys())
    
    # Prepare data for box plot
    plot_data = [distance_data[dist] for dist in distances]
    
    # Create figure and axis
    fig, ax = plt.subplots(figsize=(12, 7))
    
    # Create box plot
    box = ax.boxplot(plot_data, patch_artist=True, labels=[f'{d}m' for d in distances])
    
    # Customize box plot colors
    colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#1abc9c']
    for patch, color in zip(box['boxes'], colors[:len(distances)]):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    # Set labels and title
    ax.set_xlabel('Distance (meters)', fontsize=12)
    ax.set_ylabel('RSSI Value (dBm)', fontsize=12)
    ax.set_title('RSSI Values vs Distance | Motorola Moto G62 5G', fontsize=14, fontweight='bold')
    
    # Add grid
    ax.grid(True, linestyle='--', alpha=0.7)
    
    # Calculate and add mean annotations
    means = [np.mean(distance_data[dist]) for dist in distances]
    for i, mean in enumerate(means):
        ax.annotate(f'Mean: {mean:.2f}', 
                   (i+1, means[i]),
                   xytext=(0, 10), 
                   textcoords='offset points',
                   ha='center',
                   fontsize=9,
                   bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
    
    # Add number of samples annotation
    for i, dist in enumerate(distances):
        sample_count = len(distance_data[dist])
        min_val = min(distance_data[dist])
        ax.annotate(f'n={sample_count}', 
                   (i+1, min_val),
                   xytext=(0, -25), 
                   textcoords='offset points',
                   ha='center',
                   fontsize=9,
                   bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
    
    # Add timestamp information if available
    if selected_index is not None:
        try:
            timestamp = rssi_data[selected_index].get("timestamp", "Unknown")
            plt.figtext(0.02, 0.02, f"Selected Index: {selected_index}, Timestamp: {timestamp}", 
                      fontsize=8, ha='left')
        except IndexError:
            plt.figtext(0.02, 0.02, f"Selected Index: {selected_index} (out of range)", 
                      fontsize=8, ha='left')
    
    plt.tight_layout()
    return fig, distance_data

def print_statistics(distance_data):
    print("\nSummary Statistics:")
    print("-" * 50)
    for distance in sorted(distance_data.keys()):
        rssi_values = distance_data[distance]
        print(f"Distance: {distance} meters")
        print(f"  Number of samples: {len(rssi_values)}")
        print(f"  Min: {min(rssi_values)}")
        print(f"  Max: {max(rssi_values)}")
        print(f"  Mean: {np.mean(rssi_values):.2f}")
        print(f"  Median: {np.median(rssi_values):.2f}")
        print(f"  Standard Deviation: {np.std(rssi_values):.2f}")
        print("-" * 50)

# Main execution
file_path = "data/RSSI_DistanceMeasurements.json"
rssi_data = load_rssi_data(file_path)

if rssi_data:
    # Check if selected_index is valid
    if selected_index >= len(rssi_data):
        print(f"Warning: Selected index {selected_index} is out of range. There are only {len(rssi_data)} entries.")
        print("Using all available data for the plot.")
        fig, distance_data = create_boxplot(rssi_data)
    else:
        print(f"Using data at index {selected_index} for plot focus.")
        # We're still plotting all data, but highlighting the selected index in the plot
        fig, distance_data = create_boxplot(rssi_data, selected_index)
    
    # Print statistics
    print_statistics(distance_data)
    
    # Show the plot
    plt.show()
else:
    print("No data to plot.")