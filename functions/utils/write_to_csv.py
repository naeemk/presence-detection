import csv


def write_to_csv(file_name, *args):
    try:
        with open(file_name, 'a', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(args)
        print("Row successfully written to CSV.")
    except Exception as e:
        print(f"Error occurred while writing row to CSV: {e}")

# Example usage:
# write_to_csv("example.csv", "Column1Value", "Column2Value", "Column3Value")