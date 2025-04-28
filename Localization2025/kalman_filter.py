# Initialize Kalman filter state variables
posteri_estimate = 0.0
posteri_error_estimate = 1.0

process_variance = 1e-5  # How much we trust the model
estimated_measurement_variance = 1e-2  # How much we trust the measurements

def kalman_filter(measurement):
    global posteri_estimate, posteri_error_estimate, process_variance, estimated_measurement_variance
    
    # Prediction update
    priori_estimate = posteri_estimate
    priori_error_estimate = posteri_error_estimate + process_variance
    
    # Measurement update
    kalman_gain = priori_error_estimate / (priori_error_estimate + estimated_measurement_variance)
    posteri_estimate = priori_estimate + kalman_gain * (measurement - priori_estimate)
    posteri_error_estimate = (1 - kalman_gain) * priori_error_estimate
    
    return posteri_estimate
