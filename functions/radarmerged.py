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
            for x, y in coordinates:
                self.ax.plot(x, y, 'ro')  # 'ro' for red dots
            self.ax.set_xlabel('X')
            self.ax.set_ylabel('Y')
            self.ax.set_title('Map Based on Global Data')

            # Draw a cross intersecting at (0, 0)
            self.ax.axhline(0, color='k', linestyle='--')  # Horizontal line
            self.ax.axvline(0, color='k', linestyle='--')  # Vertical line

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
            print("coordinates: ", coordinates)

            # Clear the existing plot
            self.ax.clear()

            # Plot the new data
            for element in coordinates:
                radius = element.coordinates
                theta = [i * (2 * math.pi / 360) for i in range(0, 361)]  # Generate angles from 0 to 360 degrees
                x = [radius * math.cos(angle) for angle in theta]  # Calculate x coordinates
                y = [radius * math.sin(angle) for angle in theta]  # Calculate y coordinates
                self.ax.plot(x, y)  # Plot the circle
            self.ax.set_xlabel('X')
            self.ax.set_ylabel('Y')
            self.ax.set_title('Map Based on Global Data')

            # Draw a cross intersecting at (0, 0)
            self.ax.axhline(0, color='k', linestyle='--')  # Horizontal line
            self.ax.axvline(0, color='k', linestyle='--')  # Vertical line

            # Redraw the canvas
            self.canvas.draw()

            # Schedule the next update
            self.master.after(1000, self.update_map)


def update_global_data_solo():
    global global_data
    global_data = [10, 20, 30] 
    while True:
        print("loop of solo update global")
        # Update global data here (replace with your actual data update logic)
        # For demonstration, I'm just adding a new random integer to the list alternatively
        global_data.append(random.randint(1,30))
        time.sleep(1)  # Sleep for some time (simulating data update interval)


def update_global_data():
    global global_data
    global_data = [{'x': -2, 'y': -2}]  # Reset global data for non-solo mode
    while True:
        # Update global data here (replace with your actual data update logic)
        # For demonstration, I'm just adding a new dictionary to the list alternatively
        global_data.append({'x': len(global_data), 'y': len(global_data) ** 2})
        time.sleep(1)  # Sleep for some time (simulating data update interval)


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
