import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import time
import math
import random

class CoordinatesApp:
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
            coordinates = global_data

            # Clear the existing plot
            self.ax.clear()

            # Plot the new data
            for radius in coordinates:
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

def update_global_data():
    global global_data
    global_data = [10, 20, 30] 
    while True:
        # Update global data here (replace with your actual data update logic)
        # For demonstration, I'm just adding a new random integer to the list alternatively
        global_data.append(random.randint(1,30))
        time.sleep(1)  # Sleep for some time (simulating data update interval)

def main():
    root = tk.Tk()
    app = CoordinatesApp(root)
    root.mainloop()

if __name__ == "__main__":
    global_data = []  # List of integers representing radii of circles
    update_thread = threading.Thread(target=update_global_data, daemon=True)
    update_thread.start()
    main()
