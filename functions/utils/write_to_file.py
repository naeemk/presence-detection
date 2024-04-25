import csv

def write_to_csv(file_name, index, data):
    try:
        # Try to open the file in append mode to avoid overwriting existing data
        with open(file_name, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # Write the data to the specified column index
            writer.writerow([None] * (index - 1) + [data])
    except FileNotFoundError:
        # If the file doesn't exist, create a new file and write the data
        with open(file_name, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([None] * (index - 1) + [data])




