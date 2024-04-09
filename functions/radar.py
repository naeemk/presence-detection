import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import time

# Global variable to store data
global_data = []  # List of dictionaries, each containing 'x' and 'y' coordinates

class CoordinatesApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Coordinates Plotter")

        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.master)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        # Schedule the method to update the map based on global data
        self.master.after(1000, self.update_map)

    def update_map(self):
        # Update the map based on global data
        # Extract coordinates from the global objects
        coordinates = [(obj['x'], obj['y']) for obj in global_data]

        # Clear the existing plot
        self.ax.clear()

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

def update_global_data():
    global global_data
    while True:
        # Update global data here (replace with your actual data update logic)
        # For demonstration, I'm just adding a new dictionary to the list alternatively
        global_data.append({'x': len(global_data), 'y': len(global_data) ** 2})
        time.sleep(1)  # Sleep for some time (simulating data update interval)

def main():
    root = tk.Tk()
    app = CoordinatesApp(root)

    # Start a separate thread to update the global data
    update_thread = threading.Thread(target=update_global_data, daemon=True)
    update_thread.start()

    root.mainloop()

if __name__ == "__main__":
    main()
