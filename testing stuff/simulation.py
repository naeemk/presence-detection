
import math
import random
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import time
import sys
sys.path.append('../localization')
from objects.device import Device

from functions.utils.coordinate_difference import coordinate_difference


# Global variable for run solo option
run_solo = False


class RadarInputWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Enter Geographical Coordinates")

        self.label_lat = ttk.Label(master, text="x:")
        self.label_lat.pack()
        self.entry_lat = ttk.Entry(master)
        self.entry_lat.pack()

        self.label_long = ttk.Label(master, text="y:")
        self.label_long.pack()
        self.entry_long = ttk.Entry(master)
        self.entry_long.pack()

        # Checkbox for running solo or not
        self.run_solo_var = tk.BooleanVar(value=False)  # Default is unticked
        self.checkbox_solo = ttk.Checkbutton(master, text="Run Solo", variable=self.run_solo_var)
        self.checkbox_solo.pack()

        self.submit_button = ttk.Button(master, text="Submit", command=self.submit_coordinates)
        self.submit_button.pack()

    def submit_coordinates(self):
        global run_solo  # Access the global variable
        x = self.entry_lat.get()
        y = self.entry_long.get()
        if x and y:
            try:
                x = float(x)
                y = float(y)
                run_solo = self.run_solo_var.get()  # Get the value of the checkbox
                self.coordinates = {'x': x, 'y': y}
                self.master.destroy()  # Close the input window
            except ValueError:
                messagebox.showerror("Error", "Invalid input. Please enter numeric values for coordinates.")
        else:
            messagebox.showerror("Error", "Please enter both x and y coordinates.")


class Radar:
    def __init__(self, master, input_coordinates):
        self.master = master
        self.master.title("Coordinates Plotter")

        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.master)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        self.input_coordinates = input_coordinates

        # Schedule the method to update the map based on input coordinates
        self.master.after(1000, self.update_map)

    def update_map(self):
        # Update the map based on global data
        # Extract coordinates from the global objects
        coordinates = devices

        coordinates = devices
        print(f"[Radar] Received list of devices")
        print(f"[Radar] Printing distance of each device")

        for device in coordinates:
            print(f"{device.coordinates}")

        print(f"[Radar] Updating map based on list above")

        # Clear the existing plot
        self.ax.clear()


        increase_factor = 0.1
        max_abs_x = max(abs(coordinate_difference((input_coordinates['x'], 0), (device.coordinates[0], 0))[0]) for device in coordinates) * (1 + increase_factor)
        max_abs_y = max(abs(coordinate_difference((0, input_coordinates['y']), (0, device.coordinates[1]))[1]) for device in coordinates) * (1 + increase_factor)

        max_abs = max(max_abs_x, max_abs_y)

        # Set x and y limits centered at (0, 0)
        self.ax.set_xlim(-max_abs, max_abs)
        self.ax.set_ylim(-max_abs, max_abs)

        # Coordinates should look like this
        # coordinates = [(0, 0), (1, 1), (2, 4), (3, 9), (4, 16)]

        # Plot the new data
        legend_data = {}
        for idx, obj in enumerate(coordinates):
            x_coord = obj.coordinates[0]
            y_coord = obj.coordinates[1]
            fingerprint = obj.fingerprint
            distance = math.sqrt((x_coord - input_coordinates['x']) ** 2 + (y_coord - input_coordinates['y']) ** 2)
            relative_coord_x, relative_coord_x = coordinate_difference((input_coordinates['x'], input_coordinates['y']), (x_coord, y_coord)) 
            last_update_time = obj.check_last_modified()  # Get last update time for object
            if last_update_time is None:
                last_update_text = "Never updated"
            else:
                print(f"[update map]   last update time is {last_update_time}")
                time_elapsed = int(last_update_time)  # Time elapsed in seconds
                print(f"[update map]   time_elapsed in minutes calculated is {time_elapsed}")
                if time_elapsed < 60:
                    last_update_text = f"\nLast detected: {time_elapsed} seconds ago \nDistance: {distance:.2f} meters\nFingerprint: {fingerprint}"
                elif last_update_time < 120:
                    last_update_text = f"\nLast detected: {int(time_elapsed / 60)} minute ago \nDistance: {distance:.2f} meters\nFingerprint: {fingerprint}"
                else:
                    last_update_text = f"\nLast detected: {int(time_elapsed / 60)} minutes ago \nDistance: {distance:.2f} meters\nFingerprint: {fingerprint}"
            self.ax.plot(relative_coord_x, relative_coord_x, marker='o', markersize=5, label=f"Device {idx + 1}: {last_update_text}")  # Plot the dot

        self.ax.set_xlabel('X')
        self.ax.set_ylabel('Y')
        self.ax.set_title('Estimated position of devices')

        # Draw a cross intersecting at (0, 0)
        self.ax.axhline(0, color='k', linestyle='--', alpha=0.5)  # Horizontal line
        self.ax.axvline(0, color='k', linestyle='--', alpha=0.5)  # Vertical line

        # Add legend outside of the radar plot
        legend = self.ax.legend(loc='upper left', bbox_to_anchor=(1, 1))

        # Adjust figure size to fit legend
        self.fig.tight_layout()


        # Redraw the canvas
        self.canvas.draw()

        # Schedule the next update
        self.master.after(1000, self.update_map)


class RadarSolo:
    def __init__(self, master):
        self.master = master
        self.master.title("Coordinates Plotter")

        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.master)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        # Schedule the method to update the map based on input coordinates
        self.master.after(1000, self.update_map)

    def update_map(self):
        # Update the map based on global data
        # Extract coordinates from the global objects
        coordinates = devices
        print(f"[RadarSolo] Received list of devices")
        print(f"[RadarSolo] Printing distance of each device")

        for device in coordinates:
            print(f"{device.coordinates}")
        
        print(f"[RadarSolo] Updating map based on list above")

        # Clear the existing plot
        self.ax.clear()

        # Plot the new data
        legend_data = {}
        for idx, obj in enumerate(coordinates):
            radius = obj.coordinates[0]
            fingerprint = obj.fingerprint
            last_update_time = obj.check_last_modified()  # Get last update time for object
            if last_update_time is None:
                last_update_text = "Never updated"
            else:
                print(f"[update map]   last update time is {last_update_time}")
                time_elapsed = int(last_update_time) # Time elapsed in seconds
                print(f"[update map]   time_elapsed in minutes calculated is {time_elapsed}")
                if time_elapsed < 60:
                    last_update_text = f"\nLast detected: {time_elapsed} seconds ago \nDistance: {radius} \nFingerprint: {fingerprint}"
                elif last_update_time < 120:
                    last_update_text = f"\nLast detected: {int(time_elapsed/60)} minute ago \nDistance: {radius} \nFingerprint: {fingerprint}"
                else:
                    last_update_text = f"\nLast detected: {int(time_elapsed/60)} minutes ago \nDistance: {radius} \nFingerprint: {fingerprint}"
            theta = [i * (2 * math.pi / 360) for i in range(0, 361)]  # Generate angles from 0 to 360 degrees
            x = [radius * math.cos(angle) for angle in theta]  # Calculate x coordinates
            y = [radius * math.sin(angle) for angle in theta]  # Calculate y coordinates
            plot = self.ax.plot(x, y, label=f"Device {idx+1}: {last_update_text}")  # Plot the circle


        self.ax.set_xlabel('X')
        self.ax.set_ylabel('Y')
        self.ax.set_title('Position may be on any point on circle')

        # Draw a cross intersecting at (0, 0)
        self.ax.axhline(0, color='k', linestyle='--', alpha=0.5)  # Horizontal line
        self.ax.axvline(0, color='k', linestyle='--', alpha=0.5)  # Vertical line

        # Add legend outside of the radar plot
        legend = self.ax.legend(loc='upper left', bbox_to_anchor=(1, 1))

        # Adjust figure size to fit legend
        self.fig.tight_layout()

        # Redraw the canvas
        self.canvas.draw()

        # Schedule the next update
        self.master.after(1000, self.update_map)



def update_global_data():
    global devices
    devices = [] 
    random_x = random.randint(-10,10)
    random_y = random.randint(-10,10)
    device = Device("fing",(random_x, random_y))
    print(type(device.coordinates))
    devices.append(device)
    while True:
        # Update global data here (replace with your actual data update logic)
        # For demonstration, I'm just adding a new random integer to the list alternatively
        random_x = random.randint(-10,10)
        random_y = random.randint(-10,10)
        devices[0].update((random_x,random_y))
        time.sleep(1)  # Sleep for some time (simulating data update interval)

def radar_main():
    input_root = tk.Tk()
    coordinates_input_window = RadarInputWindow(input_root)
    input_root.mainloop()
    global input_coordinates
    input_coordinates = coordinates_input_window.coordinates
    print(f"[Radar] Received input coordinates:\n \t {input_coordinates}")
    global devices


    if input_coordinates:
        print(input_coordinates)
        if run_solo:
            #update_thread = threading.Thread(target=update_global_data_solo, daemon=True)
            #update_thread.start()
            root = tk.Tk()
            app = RadarSolo(root)
            root.mainloop()
        else:
            update_thread = threading.Thread(target=update_global_data, daemon=True)
            update_thread.start()
            root = tk.Tk()
            app = Radar(root, input_coordinates)
            root.mainloop()



if __name__ == "__main__":
    radar_main()








