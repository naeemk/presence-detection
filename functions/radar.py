import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import random
import threading
import time

class Device:
    def __init__(self, name, coordinates):
        self.name = name
        self.coordinates = coordinates

class RandomCoordinatesApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Random Coordinates Generator")

        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.master)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        self.plot_button = ttk.Button(self.master, text="Start", command=self.start_plot)
        self.plot_button.pack(side=tk.BOTTOM)

        self.running = False
        self.devices = []
        self.lock = threading.Lock()

    def start_plot(self):
        self.running = True
        self.plot_button.config(text="Stop", command=self.stop_plot)
        self.plot_thread = threading.Thread(target=self.plot_coordinates)
        self.plot_thread.start()

    def stop_plot(self):
        self.running = False
        self.plot_button.config(text="Start", command=self.start_plot)

    def plot_coordinates(self):
        while self.running:
            self.ax.clear()

            with self.lock:
                for device in self.devices:
                    x, y = device.coordinates
                    self.ax.plot(x, y, 'bo')  # 'bo' for blue dots

            self.ax.set_xlim(-50, 50)  # Set x-axis limits
            self.ax.set_ylim(-50, 50)  # Set y-axis limits
            self.ax.set_xlabel('X')
            self.ax.set_ylabel('Y')
            self.ax.set_title('Device Coordinates')

            # Draw a cross intersecting at (0, 0)
            self.ax.axhline(0, color='k', linestyle='--')  # Horizontal line
            self.ax.axvline(0, color='k', linestyle='--')  # Vertical line

            self.canvas.draw()

            time.sleep(2)  # Update interval

def main():
    root = tk.Tk()
    app = RandomCoordinatesApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
