import json

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)

config = load_config()

def KalmanFilter(rssi_list):
    # Initialize Kalman filter state variables
    posteri_estimate = rssi_list[0]  # Initial estimate
    posteri_error_estimate = config["kalman_filter"]["posteri_error_estimate"] 
    process_variance = config["kalman_filter"]["process_variance"]  # How much we trust the model
    estimated_measurement_variance = config["kalman_filter"]["estimated_measurement_variance"]  # How much we trust the measurements

    # List to store the filtered RSSI values
    filtered_rssis = []
    
    for measurement in rssi_list:
        # Prediction update
        priori_estimate = posteri_estimate
        priori_error_estimate = posteri_error_estimate + process_variance
        
        # Measurement update
        kalman_gain = priori_error_estimate / (priori_error_estimate + estimated_measurement_variance)
        posteri_estimate = priori_estimate + kalman_gain * (measurement - priori_estimate)
        posteri_error_estimate = (1 - kalman_gain) * priori_error_estimate
        
        # Add the filtered value to the list
        filtered_rssis.append(posteri_estimate)
    
    return filtered_rssis
