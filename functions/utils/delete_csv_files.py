import os

def delete_csv_files(*file_paths):
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Deleted {file_path}")
        else:
            print(f"{file_path} does not exist.")

# Example usage:
#delete_csv_files("data1.csv", "data2.csv", "data3.csv")
