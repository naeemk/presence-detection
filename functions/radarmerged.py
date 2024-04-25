import math
import random
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import time

# Global variable for run solo option
run_solo = False


class RadarInputWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Enter Geographical Coordinates")

        self.label_lat = ttk.Label(master, text="Latitude:")
        self.label_lat.pack()
        self.entry_lat = ttk.Entry(master)
        self.entry_lat.pack()

        self.label_long = ttk.Label(master, text="Longitude:")
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
        lat = self.entry_lat.get()
        long = self.entry_long.get()
        if lat and long:
            try:
                lat = float(lat)
                long = float(long)
                run_solo = self.run_solo_var.get()  # Get the value of the checkbox
                self.coordinates = {'latitude': lat, 'longitude': long}
                self.master.destroy()  # Close the input window
            except ValueError:
                messagebox.showerror("Error", "Invalid input. Please enter numeric values for coordinates.")
        else:
            messagebox.showerror("Error", "Please enter both latitude and longitude.")


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
        coordinates = []
        for el in devices:
            coordinates.append(devices.coordinates)

        # Clear the existing plot
        self.ax.clear()

        # Coordinates should look like this
        # coordinates = [(0, 0), (1, 1), (2, 4), (3, 9), (4, 16)]

        # Plot the new data
        legend_data = {}
        for x, y in coordinates:
            plot = self.ax.plot(x, y, 'ro')  # 'ro' for red dots
            legend_data[plot[0]] = f"({x}, {y})"  # Store the plot and its corresponding value

        self.ax.set_xlabel('X')
        self.ax.set_ylabel('Y')
        self.ax.set_title('Estimated position of devices')

        # Draw a cross intersecting at (0, 0)
        self.ax.axhline(0, color='k', linestyle='--', alpha=0.5)  # Horizontal line
        self.ax.axvline(0, color='k', linestyle='--', alpha=0.5)  # Vertical line

        # Add legend
        self.ax.legend(legend_data.values(), loc='upper right')

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
        
        print(f"[RadarSolo] Updating map based on this list")

        # Clear the existing plot
        self.ax.clear()

        # Plot the new data
        legend_data = {}
        for idx, obj in enumerate(coordinates):
            radius = obj.coordinates
            last_update_time = obj.check_last_modified()  # Get last update time for object
            if last_update_time is None:
                last_update_text = "Never updated"
            else:
                print(f"[update map]   last update time is {last_update_time}")
                time_elapsed = int(last_update_time) # Time elapsed in seconds
                print(f"[update map]   time_elapsed in minutes calculated is {time_elapsed}")
                if time_elapsed < 60:
                    last_update_text = f"\nLast detected: {time_elapsed} seconds ago \nDistance: {obj.radius}"
                elif last_update_time < 120:
                    last_update_text = f"\nLast detected: {int(time_elapsed/60)} minute ago \nDistance: {obj.radius}"
                else:
                    last_update_text = f"\nLast detected: {int(time_elapsed/60)} minutes ago \nDistance: {obj.radius}"
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





def radar_main(devicesparameter, sniffercords, sniffercordsready):
    input_root = tk.Tk()
    coordinates_input_window = RadarInputWindow(input_root)
    input_root.mainloop()
    global input_coordinates
    input_coordinates = coordinates_input_window.coordinates
    global devices
    devices = devicesparameter
    sniffercords[0] = input_coordinates
    sniffercordsready.set()

    if input_coordinates:
        print(input_coordinates)
        if run_solo:
            #update_thread = threading.Thread(target=update_global_data_solo, daemon=True)
            #update_thread.start()
            root = tk.Tk()
            app = RadarSolo(root)
            root.mainloop()
        else:
            #update_thread = threading.Thread(target=update_global_data, daemon=True)
            #update_thread.start()
            root = tk.Tk()
            app = Radar(root, input_coordinates)
            root.mainloop()



if __name__ == "__main__":
    radar_main()
