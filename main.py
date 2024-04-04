import threading
import queue
import time
import random

# Function to simulate sending elements to the queue at unpredictable time periods
def sender(queue):
    while True:
        # Simulate unpredictable time periods
        time.sleep(random.uniform(0.5, 2.0))
        
        # Generate a random element to send to the queue
        fingerprint = random.randint(1, 100)
        
        # Put the element into the queue
        queue.put(fingerprint)
        print(f"Sent: {fingerprint}")

# Function to process elements from the queue in real-time
def processor(queue):
    while True:
        # Get the element from the queue
        element = queue.get()
        
        # Process the element (in this case, just print it)
        print(f"Processed: {element}")
        
        # Simulate processing time
        # time.sleep(0.5)

# Create a queue
q = queue.Queue()

# Create and start the sender thread
sender_thread = threading.Thread(target=sender, args=(q,))
sender_thread.start()

# Create and start the processor thread
processor_thread = threading.Thread(target=processor, args=(q,))
processor_thread.start()

# Wait for the threads to finish (which they won't, as they run indefinitely)
sender_thread.join()
processor_thread.join()
